# ADR 0046: layered roots, read-only images and private trees

Status: accepted (Phase 3, P3-S5). Extends ADR 0040 (one native call,
manifest keys) and ADR 0022 (the tmpfs node model).

## Context

- **P3-S5:** "Read-only base images with a private writable layer per
  compartment in the tmpfs VFS; discard-on-exit mode." (SR-3.)
- **Spec section 3, Wine:**
  - each application gets its own private prefix over a read-only
    template;
  - "the Wine binaries and the template prefix are a read-only image. A
    compartment cannot modify Wine itself."
- **The manifest** names these as `[root] base` (the read-only image),
  `prefix` (a read-only template) and `writable`: "private", or
  "ephemeral", which discards on exit.

Until now a compartment's root was one directory, used as it was, and
`prefix` and `writable` were refused (ADR 0040).

Linux would use overlayfs: a merged view of an upper directory over
lower ones, with whiteouts for removed names and copy-up of what is
changed (`Documentation/filesystems/overlayfs.rst`). Keel's filesystem
is one in-memory tree whose file data is already reference-counted
(`Arc`), which allows something simpler.

## Decision

### Images: frozen trees

- **`Fs::freeze(dir)`** makes everything under a directory a read-only
  image, for good. Every node in it is marked frozen, and from then on:
  - **its data** cannot change: write, truncate and seals are EROFS;
  - **its metadata** cannot change: chmod and utimensat are EROFS, and
    reads leave its access time alone, as on a read-only filesystem;
  - **its names** cannot change: creating, removing or renaming in a
    frozen directory, or moving a name into or out of one, is EROFS;
  - **open(2) for writing** an image's file through the image's own path
    is EROFS, as on a read-only mount.

  This holds for every process, the system compartment and keel-init
  included.
- **A file in use stops it:** EBUSY, changing nothing, if a file (or
  link or device) under it is open or mapped, because an open writable
  descriptor or a shared mapping could otherwise still change it. An
  open directory does not stop it: a frozen directory refuses new names
  anyway.
- **An image is never removed:** its nodes cannot be unlinked.

### Private trees: directories copied, files shared until changed

- **`Fs::layer(into, from)`** lays a frozen image over a private
  directory:
  - each of the image's directories becomes one of the private tree's
    own, with the same permissions and times;
  - each other node (file, link, device) is entered by name, shared with
    the image.
- **Two layers:** a name the private tree already has is replaced, so a
  template prefix laid after the base overrides it, and directories
  with the same name merge.
- **No whiteouts:** because the private tree's directories are its own,
  removing or renaming in it is ordinary, and nothing like overlayfs's
  whiteouts or opaque directories is needed.
- **Copy-up:** a change to a shared node through the private tree copies
  it up first (`Fs::copy_up`). The entry gets a node of its own:
  - **contents:** the same, with file data shared until written (`Arc`);
  - **metadata:** the same permissions, times and seals;
  - **cost:** charged to the compartment (one node, and the file's
    bytes).

  This is overlayfs's rule ("when a file in the lower filesystem is
  accessed in a way the requires write-access, such as opening for write
  access, changing some metadata etc., the file is first copied"), and
  it covers:
  - open(2) for writing, and O_TRUNC;
  - chmod and fchmodat, and utimensat by path;
  - linkat, whose source is copied up first, as overlayfs does, so both
    names stay one file in the private tree.
- **Through a descriptor:** a change to an image's node through a
  descriptor opened before (fchmod, futimens on a read-only descriptor)
  is EROFS. Overlayfs would copy up there; Keel only copies up by path.
- **Hard links:** a file with two names in the image becomes two files
  in the private tree when one is copied up. Overlayfs does the same
  without its inode index ("this will 'break' the link"). `stat` of an
  image's node reports the links it had in the image.

### The native call

- **`layer(factory, into, from)`** (`+8`; the interface now has nine
  calls, under the spec's ten) freezes `from`, then lays it over `into`.
- **Rights:** it needs CREATE on the factory, ENUMERATE on `from` and
  CREATE on `into`.
- **Refusals:**

  | Case | Error |
  | --- | --- |
  | `into` is frozen | EROFS |
  | `into` is `from`, or beneath it | EINVAL |
  | a file under `from` is in use | EBUSY |
  | either is not a directory | ENOTDIR |

- **Charging:** the private directories are charged to the caller's
  compartment, which is keel-launch's, so no quota applies. Copies are
  charged to the compartment that makes them.

### keel-launch and the manifest

- **`[root] writable`** is `"private"` or `"ephemeral"`. When it is
  given, `base` and `prefix` (optional) are images:
  - **"private":** the root is `/var/keel/<name>`. The first launch makes
    it and lays the base and then the prefix over it. Later launches use
    it as it is, so the application's changes are kept.
  - **"ephemeral":** the root is `/run/keel/<name>-<pid>`, made and laid
    each launch and removed, everything in it, when the compartment has
    ended. A leftover one from a launch that did not end cleanly is
    removed first.
- **`writable` left out:** the root is `base` itself, as before.
- **`prefix` without `writable`:** refused.
- **The name:** a manifest's `name` may no longer be `.` or `..`, since
  it names the private tree's directory.

## Evidence

- **Host tests** (`keel_core::vfs`, 7):
  - an image refuses every change (EROFS), including through a path
    inside it, and keeps its access time a day later, when relatime
    would stamp another file's;
  - a frozen file with F_SEAL_GROW: a write past its end is EROFS, the
    read-only filesystem, not the seal's EPERM;
  - an open file stops freezing (EBUSY) and an open directory does not;
  - a layer shares files and copies directories, and the private tree
    adds, removes and renames freely;
  - writing copies up, and the image keeps its own, through a symbolic
    link and deeper directories;
  - copies and private directories are charged; a full quota refuses
    the copy and changes nothing;
  - a later layer overrides an earlier one, and directories merge.
- **Manifest tests:**
  - `prefix` and `writable` parse;
  - a relative prefix, a prefix without `writable` and an unknown
    `writable` fail;
  - the name `..` is refused.
- **`launch.layered`** (phase 3): three launches through `keel-init
  --launch`, all over the same base (`etc/greeting`, `etc/keep`,
  `lib/x`) and prefix (`etc/greeting`, `etc/extra`). Afterwards the
  kernel finds the images unchanged and still frozen (a write by the
  kernel itself EROFS), the private tree with the change, and the
  ephemeral tree gone.
  - **First, `writable = "private"`:** in launchprobe's `layered` mode
    the program finds:
    - the prefix's greeting and the base's other files;
    - its write to a base file reads back as its own;
    - new, removed and renamed names, and a chmod, work.
  - **Again, the same private tree:** the changes are all there.
  - **Then `writable = "ephemeral"`:** a fresh tree, without any of
    them.
- **`exec.launch`** (launchprobe check 13), with the native call:
  - refusals: a factory without CREATE (EBADF), a file (ENOTDIR), a
    tree over itself (EINVAL), one inside its image (EINVAL);
  - a tree with an open file is EBUSY, and stays unfrozen and writable;
  - after a layer: the private copy written; the image unwritable
    (EROFS for open for writing and for a new name); a layer over the
    image, or inside it, EROFS.
- **Mutations,** 12, each caught:

  | Mutation | Caught by |
  | --- | --- |
  | rename into or out of an image allowed | host test (an image cannot change) |
  | an image's access time stamped by reads | host test, once its clock was moved a day on (it first survived: the test's clock did not move) |
  | freezing a tree with an open file | host test |
  | a later layer not replacing an earlier one's names | host test |
  | `stat` counting the private trees' names | host test |
  | new names in an image's directory | host tests |
  | open for writing not copying up | `launch.layered` (exit 73) and `exec.launch` (13) |
  | copy-up doing nothing | `launch.layered` (73) and `exec.launch` (13) |
  | `write_as`'s own EROFS check removed | host test of a sealed frozen file (it first survived: the resize path refuses too, but with the seal's EPERM before EROFS) |
  | an ephemeral tree not removed | `launch.layered` |
  | a private tree laid again over its changes | `launch.layered` (again: 71) |
  | the prefix not laid | `launch.layered` (72) |

## Not yet covered

- **`[[grant]]`:** mounting more of the system's tree into a compartment,
  with rights, is not part of P3-S5 and is still refused.
- **Copy-up through a descriptor** (fchmod, futimens): EROFS, as above.
- **Freezing at build time:** images are frozen at their first layer, by
  whoever launches first. An image built into the boot tree could be
  frozen at boot instead.
- **Removing an image,** to replace it, is not possible. A new version
  goes at a new path.

## Motivation
Creating management plane for infused/composed eBPF elements in Linux kernel (be it for networking, observability) is a new problem which is coming forth with emergence of eBPF adoption.
That the developer/operator community is aware of the same is clear by recent efforts in building tooling such as ``Bumblebee (solo.io)``, ``L3AF (Walmart led)``, ``bpftool-gen`` etc. coming from heavy eBPF users.

A key goal for such tooling is to obviate the need for management-plane developers to be aware of eBPF nitty-gritties by presenting industry standard mechanisms for accessing/configuring eBPF functionalities. 
### Bumblebee (solo.io)

#### Pros:
1. Provides ancilliary facilities like hosting of signed, OCI bpf images (albeit only for observability).
2. Actively maintained (??).
3. Does not work with binary code.
#### Cons:
1. Forces users to use their IDE for develop.
2. Presently only support restricted class of maps and hookpoints (kprobe)
3. Cannot generate APIs for existing eBPF modules.

### bpftool-gen

### Pros:
1. The official ``libbpf`` tool.
2. Will always be in-sync with latest ``libbpf``
3. Actively maintained.
4. Works with binary images

### Cons:
1. Outputs **C** code file, and not industry standard APIs like gRPC, REST etc.

## Proposal
Start from binary code and 
1. Identify all maps and their internal data-strucutures
2. Provide following map entry manipulation APIs (gRPC, REST) 
    1. Read
    2. Write
    3. Update
    4. Delete
3. Take user input to select only necessary APIs and remove the rest.
4. For high perf data-op can we also think of shared memory ?
5. **Q:** How would K8s<->management-plane interaction happen? is there a standardized API for the same ?

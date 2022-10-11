# OPENED
Temporary repository to track OPENED issues. Please self-assign relevant issues. 
LPC 2022 blurb describing initial prototype is here: https://lpc.events/event/16/contributions/1370/

## Setup Instructions

Infra Latest Ubuntu Distribution 22.04 preferred

Setup Dependencies

1. Install for eBPF: 
Follow this link to set up a working eBPF environment
 https://github.com/xdp-project/xdp-tutorial/blob/master/setup_dependencies.org
bpftool
clang 
llvm
Linux kernel 5.16+
Linux Headers: sudo apt install linux-headers-$(uname -r)
 
1.a) If you can get the simple XDP_PASS program to work, you have a working setup. https://github.com/xdp-project/xdp-tutorial/blob/master/basic01-xdp-pass/README.org

2. Software dependencies to be installed for OPENED
 Codequery: ruben2020/codequery: A code-understanding, code-browsing or code-search tool. This is a tool to index, then query or search C, C++, Java, Python, Ruby, Go and Javascript source code. It builds upon the databases of cscope and ctags, and provides a nice GUI tool. (github.com)
    TXL: Txl Home Page
    Coccinelle:https://coccinelle.gitlabpages.inria.fr/website/


3. eBPF monoliths: to be cloned
Katran: facebookincubator/katran: A high performance layer 4 load balancer (github.com)
Cilium: cilium/cilium: eBPF-based Networking, Security, and Observability (github.com)
Mizar: CentaurusInfra/mizar: Mizar – Experimental, High Scale and High Performance Cloud Network https://mizar.readthedocs.io (github.com)
RakeLimit: https://github.com/cloudflare/rakelimit

from bcc import BPF

ebpf_program = r"""
int process_start(void *ctx) {
   bpf_trace_printk("A new process was started!");
   return 0;
}
"""
prog = BPF(text=ebpf_program)
execve_syscall = prog.get_syscall_fnname("execve")
prog.attach_kprobe(event=execve_syscall, fn_name="process_start")
prog.trace_print()
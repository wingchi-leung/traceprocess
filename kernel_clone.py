#!/usr/bin/env python
# coding=utf-8

from bcc import BPF
import psutil
import sys

# usage: kernel_clone.py  app's name
# e.g. : kernel_clone.py firefox


def get_pid_byName():
    if len(sys.argv) > 1:
        name = (sys.argv[1])
    else:
        return

    while(1):
        pids = psutil.process_iter()

        for pid in pids:
            if pid.name() == name:
                print("you are tracing pid: %d" % pid.pid)
                return pid.pid


pid = get_pid_byName()

bpf_text = """
    # include <linux/sched.h>


    struct data_t {
        u32 pid;
        u32 tgid ;
        
        
        char comm[TASK_COMM_LEN] ;
    };
    //创建一个bpf表叫做events
    BPF_PERF_OUTPUT(events);

    int do_trace(struct pt_regs *ctx, struct kernel_clone_args *args){

        struct data_t data = {} ;
        pid_t pid = PT_REGS_RC(ctx) ;

        UID_FILTER
        int flag=0;
        // 获取了新创建进程/线程的父进程的task_struct 
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        // 循环5次遍历父进程链
        for(int i=0;i<5;i++){
            if(task->pid==1 ){
                return 0;
            }
           
            if(task->pid==PID||task->tgid==PID){
                flag=1;
                break;
            }
            task=task->parent;
        }
        if (flag==0) return 0 ;
        data.pid = pid;
        data.tgid = bpf_get_current_pid_tgid()>>32;  
        bpf_get_current_comm(&data.comm, sizeof(data.comm)) ;
        events.perf_submit(ctx,&data,sizeof(data)) ;
        return 0;
    }

"""


if pid:
    bpf_text = bpf_text.replace("UID_FILTER", 'pid_t PID=%d;' % pid)
else:
    bpf_text = bpf_text.replace("UID_FILTER", 'pid_t PID=0;')


b = BPF(text=bpf_text)
b.attach_kretprobe(event="kernel_clone", fn_name="do_trace")


print("%-18s %-16s %-6s %5s " % ("COUNT", "COMM", "PID", "TGID"))


count = 0
# 定义python函数来处理从事件流中读取事件


def print_event(cpu, data, size):

    global count
    count += 1
    # 使用bcc根据前面C语言部分的定义自动生成对应的数据结构
    event = b["events"].event(data)
    print("%-18.9f %-16s %-6d %5d" % (count, event.comm, event.pid, event.tgid
                                      ))


# 和print_event函数相关联
b["events"].open_perf_buffer(print_event)
# 等待事件
while 1:
    b.perf_buffer_poll()

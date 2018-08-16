## What is this?

This repo is an **unofficial** CIRALabs "feeds" for [OpenWrt](https://openwrt.org "OpenWrt"). This project is experimental, and technical support will be limited.

In OpenWrt/Lede, a ["feeds"](https://wiki.openwrt.org/doc/devel/feeds "feeds") is a collection of software components (applications, libraries, kernel-modules, ...) that you can integrate into your OpenWrt/Lede system.

## How can I use them?

I assume that you already have a working OpenWrt/Lede workspace, then add the following line into "feeds.conf.default" (You will find it under the top dir of your workspace).

    src-git cira https://github.com/CIRALabs/SHG-feeds

then execute:

	scripts/feeds update -f cira
	scripts/feeds install -a -p cira

Now you will be able to see extra packages via `make menuconfig`.

## What do we have here?

TBD


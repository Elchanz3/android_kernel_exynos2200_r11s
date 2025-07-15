# SPDX-License-Identifier: GPL-2.0
dtbo-y += samsung/r11s/r11s_eur_openx_w01_r05.dtbo
dtbo-y += samsung/r11s/r11s_eur_openx_w01_r00.dtbo
dtbo-y += samsung/r11s/r11s_eur_openx_w01_r01.dtbo
dtbo-y += samsung/r11s/r11s_eur_openx_w01_r03.dtbo
dtbo-y += samsung/r11s/r11s_eur_openx_w01_r02.dtbo
dtbo-y += exynos/board/univ/s5e9925-universal9925_rev17.dtbo
dtbo-y += exynos/board/univ/s5e9925-universal9925_rev1b.dtbo
dtbo-y += exynos/board/univ/s5e9925-universal9925_rev00.dtbo
dtbo-y += exynos/board/erd/s5e9925_s6165-erd9925.dtbo
dtbo-y += exynos/board/erd/s5e9925-erd9925_r13.dtbo
dtbo-y += exynos/board/erd/s5e9925-erd9925.dtbo
dtbo-y += exynos/board/erd/s5e9925_s6165-erd9925_r17.dtbo
dtbo-y += exynos/board/erd/s5e9925-erd9925_r18.dtbo
dtb-y += exynos/s5e9925.dtb

targets += dtbs
DTB_LIST  := $(dtb-y) $(dtbo-y)
always    := $(DTB_LIST)

dtbs: $(addprefix $(obj)/, $(DTB_LIST))

clean-files := *.dtb*

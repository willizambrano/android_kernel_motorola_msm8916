#!/bin/bash
# Compiler Powered_by_AMDfx6300
#

BUILD_START=$(date +"%s")
blue='\033[0;34m'
cyan='\033[0;36m'
yellow='\033[0;33m'
red='\033[0;31m'
nocol='\033[0m'

echo -e "Borrando basura"
make clean && make mrproper

export CROSS_COMPILE=/home/william/linaro4.9/bin/arm-eabi-
export ARCH=arm
export KBUILD_BUILD_USER="WilliamZambrano"
export KBUILD_BUILD_HOST="AMDfx6300"

make osprey_defconfig
make menuconfig
echo -e "$yellow*****************************************************"
echo "       Compilando Evolution_Kernel         "
echo -e "*****************************************************$nocol"

make -j6 zImage CONFIG_DEBUG_SECTION_MISMATCH=y CONFIG_NO_ERROR_ON_MISMATCH=y
make -j6 dtimage CONFIG_DEBUG_SECTION_MISMATCH=y CONFIG_NO_ERROR_ON_MISMATCH=y
make -j6 modules CONFIG_DEBUG_SECTION_MISMATCH=y CONFIG_NO_ERROR_ON_MISMATCH=y

mkdir -p evolution_install
make -j6 modules_install INSTALL_MOD_PATH=evolution_install INSTALL_MOD_STRIP=1

BUILD_END=$(date +"%s")
DIFF=$(($BUILD_END - $BUILD_START))
echo -e "$yellow Construcción completada en $(($DIFF / 60)) minuto(s) y $(($DIFF % 60)) segundos.$nocol"

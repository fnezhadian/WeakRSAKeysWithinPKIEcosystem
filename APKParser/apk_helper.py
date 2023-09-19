# -*- coding: utf-8 -*-
import io
import os
import subprocess
from collections import OrderedDict
from elftools.elf.elffile import ELFFile
import pefile


api_year = {
            "1": "2008",
            "2": "2009",
            "3": "2009",
            "4": "2009",
            "5": "2009",
            "6": "2009",
            "7": "2010",
            "8": "2010",
            "9": "2010",
            "10": "2011",
            "11": "2011",
            "12": "2011",
            "13": "2011",
            "14": "2011",
            "15": "2011",
            "16": "2012",
            "17": "2012",
            "18": "2013",
            "19": "2013",
            "20": "2014",
            "21": "2014",
            "22": "2015",
            "23": "2015",
            "24": "2016",
            "25": "2016",
            "26": "2017",
            "27": "2017",
            "28": "2018",
            "29": "2019",
            "30": "2020",
            "31": "2021",
            "32": "2022",
            }

valid_releases = {
         "1.0": {"API": "1", "date": "September 23, 2008",  "year": "2008", "codename": ""},
         "1.1": {"API": "2", "date": "February 9, 2009",    "year": "2009", "codename": ""},
         "1.5": {"API": "3", "date": "April 27, 2009",      "year": "2009", "codename": "Cupcake"},
         "1.6": {"API": "4", "date": "September 15, 2009",  "year": "2009", "codename": "Donut"},
         "2.0": {"API": "5", "date": "October 27, 2009",    "year": "2009", "codename": "Eclair"},
       "2.0.1": {"API": "6", "date": "December 3, 2009",    "year": "2009", "codename": "Eclair"},
         "2.1": {"API": "7", "date": "January 11, 2010",    "year": "2010", "codename": "Eclair"},
         "2.2": {"API": "8", "date": "May 20, 2010",        "year": "2010", "codename": "Froyo"},
       "2.2.1": {"API": "8", "date": "September 27, 2010",  "year": "2010", "codename": "Froyo"},
       "2.2.2": {"API": "8", "date": "January 21, 2011",    "year": "2011", "codename": "Froyo"},
       "2.2.3": {"API": "8", "date": "November 21, 2011",   "year": "2011", "codename": "Froyo"},
         "2.3": {"API": "9", "date": "December 6, 2010",    "year": "2010", "codename": "Gingerbread"},
       "2.3.1": {"API": "9", "date": "December 22, 2010",   "year": "2010", "codename": "Gingerbread"},
       "2.3.2": {"API": "9", "date": "January 21, 2011",    "year": "2011", "codename": "Gingerbread"},
       "2.3.3": {"API": "10", "date": "February 9, 2011",   "year": "2011", "codename": "Gingerbread"},
       "2.3.4": {"API": "10", "date": "April 28, 2011",     "year": "2011", "codename": "Gingerbread"},
       "2.3.5": {"API": "10", "date": "July 25, 2011",      "year": "2011", "codename": "Gingerbread"},
       "2.3.6": {"API": "10", "date": "September 2, 2011",  "year": "2011", "codename": "Gingerbread"},
       "2.3.7": {"API": "10", "date": "September 21, 2011 ","year": "2011", "codename": "Gingerbread"},
         "3.0": {"API": "11", "date": "February 22, 2011",  "year": "2011", "codename": "Honeycomb"},
         "3.1": {"API": "12", "date": "May 10, 2011",       "year": "2011", "codename": "Honeycomb"},
         "3.2": {"API": "13", "date": "July 15, 2011",      "year": "2011", "codename": "Honeycomb"},
       "3.2.1": {"API": "13", "date": "September 20, 2011", "year": "2011", "codename": "Honeycomb"},
       "3.2.2": {"API": "13", "date": "September 30, 2011", "year": "2011", "codename": "Honeycomb"},
       "3.2.4": {"API": "13", "date": "December 15, 2011",  "year": "2011", "codename": "Honeycomb"},
       "3.2.6": {"API": "13", "date": "February 15, 2012",  "year": "2012", "codename": "Honeycomb"},
         "4.0": {"API": "14", "date": "October 18, 2011",   "year": "2011", "codename": "Ice Cream Sandwich"},
       "4.0.1": {"API": "14", "date": "October 19, 2011",   "year": "2011", "codename": "Ice Cream Sandwich"},
       "4.0.2": {"API": "14", "date": "November 28, 2011",  "year": "2011", "codename": "Ice Cream Sandwich"},
       "4.0.3": {"API": "15", "date": "December 16, 2011",  "year": "2011", "codename": "Ice Cream Sandwich"},
       "4.0.4": {"API": "15", "date": "March 28, 2012",     "year": "2012", "codename": "Ice Cream Sandwich"},
         "4.1": {"API": "16", "date": "July 9, 2012",       "year": "2012", "codename": "Jelly Bean"},
       "4.1.1": {"API": "16", "date": "July 9, 2012",       "year": "2012", "codename": "Jelly Bean"},
       "4.1.2": {"API": "16", "date": "October 9, 2012",    "year": "2012", "codename": "Jelly Bean"},
         "4.2": {"API": "17", "date": "November 13, 2012",  "year": "2012", "codename": "Jelly Bean"},
       "4.2.1": {"API": "17", "date": "November 27, 2012",  "year": "2012", "codename": "Jelly Bean"},
       "4.2.2": {"API": "17", "date": "February 11, 2013",  "year": "2013", "codename": "Jelly Bean"},
         "4.3": {"API": "18", "date": "July 24, 2013",      "year": "2013", "codename": "Jelly Bean"},
       "4.3.1": {"API": "18", "date": "October 3, 2013",    "year": "2013", "codename": "Jelly Bean"},
         "4.4": {"API": "19", "date": "October 31, 2013",   "year": "2013", "codename": "KitKat"},
       "4.4.1": {"API": "19", "date": "December 5, 2013",   "year": "2013", "codename": "KitKat"},
       "4.4.2": {"API": "19", "date": "December 9, 2013",   "year": "2013", "codename": "KitKat"},
       "4.4.3": {"API": "19", "date": "June 2, 2014",       "year": "2014", "codename": "KitKat"},
       "4.4.4": {"API": "19", "date": "June 19, 2014",      "year": "2014", "codename": "KitKat"},
        "4.4W": {"API": "20", "date": "June 25, 2014",      "year": "2014", "codename": "KitKat"},
      "4.4W.1": {"API": "20", "date": "September 6, 2014",  "year": "2014", "codename": "KitKat"},
      "4.4W.2": {"API": "20", "date": "October 21, 2014",   "year": "2014", "codename": "KitKat"},
         "5.0": {"API": "21", "date": "November 4, 2014",   "year": "2014", "codename": "Lollipop"},
       "5.0.1": {"API": "21", "date": "December 2, 2014",   "year": "2014", "codename": "Lollipop"},
       "5.0.2": {"API": "21", "date": "December 19, 2014",  "year": "2014", "codename": "Lollipop"},
         "5.1": {"API": "22", "date": "March 2, 2015",      "year": "2015", "codename": "Lollipop"},
       "5.1.1": {"API": "22", "date": "April 20, 2015",     "year": "2015", "codename": "Lollipop"},
         "6.0": {"API": "23", "date": "October 2, 2015",    "year": "2015", "codename": "Marshmallow"},
       "6.0.1": {"API": "23", "date": "December 7, 2015",   "year": "2015", "codename": "Marshmallow"},
         "7.0": {"API": "24", "date": "August 22, 2016",    "year": "2016", "codename": "Nougat"},
         "7.1": {"API": "25", "date": "October 4, 2016",    "year": "2016", "codename": "Nougat"},
       "7.1.1": {"API": "25", "date": "December 1, 2016",   "year": "2016", "codename": "Nougat"},
       "7.1.2": {"API": "25", "date": "April 2, 2017",      "year": "2017", "codename": "Nougat"},
         "8.0": {"API": "26", "date": "August 21, 2017",    "year": "2017", "codename": "Oreo"},
         "8.1": {"API": "27", "date": "December 5, 2017",   "year": "2017", "codename": "Oreo"},
           "9": {"API": "28", "date": "August 6, 2018",     "year": "2018", "codename": "Pie"},
          "10": {"API": "29", "date": "September 3, 2019",  "year": "2019", "codename": "Android10"},
          "11": {"API": "30", "date": "September 8, 2020",  "year": "2020", "codename": "Android11"},
          "12": {"API": "31", "date": "October 4, 2021",    "year": "2021", "codename": "Android12"},
         "12L": {"API": "32", "date": "March 7, 2022",      "year": "2022", "codename": "Android12L"},
     #"ddddddd": {"API": "", "date": "", "year": "", "codename": ""},
         }


def jadx_decode(apk_path, dest_folder, tool_source):
    if not os.path.isdir(dest_folder):
        print(dest_folder)
        raise AssertionError("ERROR: unsupported source, has to be a FOLDER")

    if not os.path.isfile(apk_path):
        print(apk_path)
        raise AssertionError("ERROR: unsupported source, has to be a FILE")

    fsize = os.path.getsize(apk_path)

    # "/media/user01/NVME_1TB/APK_TESTS/jadx/build/jadx/bin/jadx" --threads-count 1 --show-bad-code --deobf --deobf-min 2 --deobf-use-sourcename --deobf-parse-kotlin-metadata --output-dir "jadx_test"

    # file MUST be larger than 4KB
    # if not --> ssdeep: Did not process files large enough to produce meaningful results
    jadx_ret = ""
    status = "ERR"
    if fsize > 4096:
        command = [tool_source,
                   "--threads-count", "1",
                   "--show-bad-code",
                   "--deobf",
                   "--deobf-min", "2",
                   "--deobf-use-sourcename",
                   "--deobf-parse-kotlin-metadata",
                   "--output-dir",
                   dest_folder,
                   apk_path
                   ]

        try:
            jadx_ret = subprocess.check_output(command,
                                               stderr=subprocess.STDOUT,
                                               shell=False)

            return_code = 0
        except subprocess.CalledProcessError as ex:
            jadx_ret = ex.output
            return_code = ex.returncode

        if return_code == 0:
            status = "OK"
        else:
            status = "ERR"

    try:
        str_result = jadx_ret.decode('utf-8')
        # print "string is UTF-8, length %d bytes" % len(string)
        return (jadx_ret, status)
    except UnicodeError:
        # print "string is not UTF-8"
        str_result = jadx_ret.encode('utf-8')
        return (str_result, status)
    except AttributeError:
        str_result = jadx_ret.encode('utf-8')
        return (str_result, status)


def apkanalyzer_dex(data_path, sdk_tool_path):
    if not os.path.isfile(data_path):
        raise AssertionError("ERROR: unsupported source, has to be a FILE")

    command = [sdk_tool_path,
               "dex",
               "packages",
               data_path,
               ]
    try:
        ret = subprocess.check_output(command,
                                      stderr=subprocess.STDOUT,
                                      shell=False)
        returncode = 0
    except subprocess.CalledProcessError as ex:
        ret = ex.output
        returncode = ex.returncode

    status = ""
    if returncode == 0:
        status = "OK"
    else:
        status = "ERR"

    return (ret)


def clamav_scan(data_path, out_log_file):
    if not os.path.isdir(data_path):
        print(data_path)
        raise AssertionError("ERROR: unsupported source, has to be a FOLDER")

    command = ["clamscan",
               "--infected",
               "--suppress-ok-results",
               "--recursive=yes",
               "--remove=no",
               "--phishing-scan-urls=yes",
               "--normalize=no",
               "--scan-pe=yes",
               "--scan-elf=yes",
               "--scan-ole2=yes",
               "--scan-pdf=yes",
               "--scan-swf=yes",
               "--scan-html=yes",
               "--scan-xmldocs=yes",
               "--scan-hwp3=yes",
               "--scan-archive=yes",
               "--nocerts",
               data_path,
               ]
    try:
        ret = subprocess.check_output(command,
                                      stderr=subprocess.STDOUT,
                                      shell=False)
        returncode = 0
    except subprocess.CalledProcessError as ex:
        ret = ex.output
        returncode = ex.returncode

    status = ""
    if returncode == 0:
        status = "OK"
    else:
        status = "ERR"

    return (ret)


def parse_elf(filepath):
    decoded = False
    with io.open(filepath, 'rb') as rif:
        try:
            elf = ELFFile(rif)
            all_items = OrderedDict()
            for k, v in elf._parse_elf_header().items():
                all_items[k] = v
            decoded = True
        except Exception as e:
            decoded = False

        parsed = OrderedDict()
        parsed["Class"] = ""  # EI_CLASS ELFCLASS32  --> ELF32
        parsed["Data"] = ""  # EI_DATA ELFDATA2LSB  --> 2's complement, little endian
        parsed["Elf_Version"] = ""  # EI_VERSION EV_CURRENT --> 1 (current)
        parsed["OS_ABI"] = ""  # EI_OSABI ELFOSABI_SYSV --> UNIX - System V
        parsed["ABI_Version"] = ""  # EI_ABIVERSION 0 --> 0
        parsed["Type"] = ""  # e_type ET_DYN --> DYN (Shared object file)
        parsed["Machine"] = ""  # e_machine EM_ARM --> ARM
        # parsed["Version"] = ""  # e_version EV_CURRENT --> EI_VERSION EV_CURRENT

    if decoded == True:
        for k, v in all_items.items():
            if k == "e_ident":
                for xx, yy in v.items():
                    if xx == "EI_CLASS":
                        if str(yy) == "ELFCLASS32":
                            parsed["Class"] = "ELF32"
                        elif str(yy) == "ELFCLASS64":
                            parsed["Class"] = "ELF64"
                        else:
                            print("-----------------")
                            print(filepath)
                            print(yy)
                            raise
                    elif xx == "EI_DATA":
                        if str(yy) == "ELFDATA2LSB":
                            # 2's complement, little endian
                            parsed["Data"] = "2cLE"
                        elif str(yy) == "ELFDATA2MSB":
                            # 2's complement, big endian
                            parsed["Data"] = "2cBE"
                        else:
                            print("-----------------")
                            print(filepath)
                            print(yy)
                            raise
                    elif xx == "EI_VERSION":
                        if str(yy) == "EV_CURRENT":
                            parsed["Elf_Version"] = "1"
                        else:
                            print("-----------------")
                            print(filepath)
                            print(yy)
                            raise
                    elif xx == "EI_OSABI":
                        if str(yy) == "ELFOSABI_SYSV":
                            parsed["OS_ABI"] = "SYSV"
                        elif str(yy) == "ELFOSABI_LINUX":
                            # UNIX - GNU
                            parsed["OS_ABI"] = "LINUX"
                        elif str(yy) == "ELFOSABI_FREEBSD":
                            # UNIX - FreeBSD
                            parsed["OS_ABI"] = "FREEBSD"
                        elif str(yy) == "ELFOSABI_SOLARIS":
                            # UNIX - Solaris
                            parsed["OS_ABI"] = "SOLARIS"
                        else:
                            print("-----------------")
                            print(filepath)
                            print(yy)
                            raise
                    elif xx == "EI_ABIVERSION":
                        if str(yy) == "0":
                            parsed["ABI_Version"] = "0"
                        elif str(yy) == "1":
                            parsed["ABI_Version"] = "1"
                        else:
                            print("-----------------")
                            print(filepath)
                            print(yy)
                            raise
            elif k == "e_type":
                if str(v) == "ET_DYN":
                    parsed["Type"] = "DYN"
                elif str(v) == "ET_REL":
                    parsed["Type"] = "REL"
                elif str(v) == "ET_EXEC":
                    parsed["Type"] = "EXEC"
                elif str(v) == "ET_CORE":
                    # CORE (Core file)
                    parsed["Type"] = "CORE"
                else:
                    print("-----------------")
                    print(filepath)
                    print(v)
                    raise
            elif k == "e_machine":
                if "_" in str(v):
                    parsed["Machine"] = str(v).split("_")[1].strip()
                else:
                    parsed["Machine"] = "UNKNOWN"

        return parsed
    else:
        return {}


def xapkdc_apk_meta(jdata):
    keep_names = [
                  "Android",                   "JVM",
                  "Android SDK",                   "Android SignApk",
                  "Java",                   "JDK",
                  "BASIC",                  "Basic4Android",
                  "ZIP",                  "Unity",
                  "www.HiAPK.com",                  "d2j-apk-sign",
                  "Unicom SDK",                  "Bangcle Protection",
                  "COMEX SignApk",                  "Apple JDK",
                  "ApkSigner",                  "IKVM.NET",
                  "DexGuard",                  "MOTODEV Studio for Android",
                  "PangXie",                  "ApkEditor",
                  "AntiLVL",                  "Android Gradle",
                  "Eclipse",                  "APK Signature Scheme",
                  "SecShell",                  "iJiami",
                  "APKProtect",                  "Mobile Tencent Protect",
                  "jiagu",                  "IBM JDK",
                  "JetBrains",                  "DexProtector",
                  "Baidu Protection",                  "SecNeo",
                  "Nagapt Protection",                  "Alibaba Protection",
                  "Qihoo 360 Protection",                  "NQ Shield",
                  "dex2jar",                  "AppSolid",
                  "Medusah",                  "Tencent Protection",
                  "yidun",                  "Walle",
                  "Android Maven Plugin",                  "Kotlin",
                  "Hdus-Wjus",                  "dotools sign apk",
                  "Apache Ant",                  "ApkProtector",
                  "BEA WebLogic",                  "Radialix",
                  "signupdate",                  "DxShield",
                  "qdbh",                  "Kiro",
                  "IL2CPP",                  "SingleJar",
                  "LIAPP",                  "Android Jetpack",
                  "Proguard",                  "tiny-sign",
                  "Android apksigner",                  "Baidu Signature platform",
                  "Google Play",                  "ApkToolPlus",
                  "BundleTool",                  "HTML",
                  "signatory",                  "VDog",
                  "AppGuard",                  "Tencent Legu",
                  "Unknown",
                  "SandHook",
                  "apk-signer",
                  "PseudoApkSigner",
                  ]

    xapk_os = ""
    xapk_vm = ""
    xapk_andro_sdk = ""
    xapk_tool = set()
    xapk_apk_tool = set()
    xapk_lang = set()
    xapk_library = set()
    xapk_format = ""
    xapk_sigtool = ""
    xapk_protector = ""

    for xit in jdata["detects"][0]["values"]:
        if not "parentfilepart" in xit:

            if xit["type"] == "Operation system":
                if xit["name"] == "Android":
                    # {'info': '', 'name': 'Android', 'string': 'Operation system: Android(2.43)', 'type': 'Operation system', 'version': '2.43'}
                    xapk_os = xit["string"].replace("Operation system: ", "").strip()
                else:
                    print(xit)
                    raise AssertionError("ERROR: missed XAPKDC info field")

            elif xit["type"] == "Virtual machine":
                if xit["name"] == "JVM":
                    # {'info': '', 'name': 'JVM', 'string': 'Virtual machine: JVM', 'type': 'Virtual machine', 'version': ''}
                    xapk_vm = xit["string"].replace("Virtual machine: ", "").strip()
                else:
                    print(xit)
                    raise AssertionError("ERROR: missed XAPKDC info field")

            elif xit["type"] == "Tool":
                if xit["name"] == "Android SDK":
                    # {'info': '', 'name': 'Android SDK', 'string': 'Tool: Android SDK(API 9)', 'type': 'Tool', 'version': 'API 9'}
                    xapk_andro_sdk = xit["string"].replace("Tool: ", "").strip()
                else:
                    # {'info': '', 'name': 'JDK', 'string': 'Tool: JDK(1.6.0_12)', 'type': 'Tool', 'version': '1.6.0_12'}
                    # {'info': '', 'name': 'www.HiAPK.com', 'string': 'Tool: www.HiAPK.com', 'type': 'Tool', 'version': ''}
                    # {'info': '', 'name': 'Apple JDK', 'string': 'Tool: Apple JDK(1.6.0_13)', 'type': 'Tool', 'version': '1.6.0_13'}
                    # {'info': '', 'name': 'IKVM.NET', 'string': 'Tool: IKVM.NET', 'type': 'Tool', 'version': ''}
                    # {'info': '', 'name': 'MOTODEV Studio for Android', 'string': 'Tool: MOTODEV Studio for Android(1.3.0)', 'type': 'Tool', 'version': '1.3.0'}
                    # {'info': '', 'name': 'Android Gradle', 'string': 'Tool: Android Gradle(2.1.3)', 'type': 'Tool', 'version': '2.1.3'}
                    # {'info': 'ADT', 'name': 'Eclipse', 'string': 'Tool: Eclipse[ADT]', 'type': 'Tool', 'version': ''}
                    # {'info': '', 'name': 'IBM JDK', 'string': 'Tool: IBM JDK(1.7.0)', 'type': 'Tool', 'version': '1.7.0'}
                    # {'info': '', 'name': 'JetBrains', 'string': 'Tool: JetBrains', 'type': 'Tool', 'version': ''}
                    # {'info': '', 'name': 'Walle', 'string': 'Tool: Walle', 'type': 'Tool', 'version': ''}
                    # {'info': '', 'name': 'Android Maven Plugin', 'string': 'Tool: Android Maven Plugin', 'type': 'Tool', 'version': ''}
                    # {'info': '', 'name': 'Apache Ant', 'string': 'Tool: Apache Ant(1.8.2)', 'type': 'Tool', 'version': '1.8.2'}
                    # {'info': '', 'name': 'BEA WebLogic', 'string': 'Tool: BEA WebLogic', 'type': 'Tool', 'version': ''}
                    # {'info': '', 'name': 'Radialix', 'string': 'Tool: Radialix(3.0)', 'type': 'Tool', 'version': '3.0'}
                    # {'info': '', 'name': 'SingleJar', 'string': 'Tool: SingleJar', 'type': 'Tool', 'version': ''}
                    # {'info': '', 'name': 'Google Play', 'string': 'Tool: Google Play', 'type': 'Tool', 'version': ''}
                    # {'info': '', 'name': 'ApkToolPlus', 'string': 'Tool: ApkToolPlus', 'type': 'Tool', 'version': ''}
                    # {'info': '', 'name': 'BundleTool', 'string': 'Tool: BundleTool', 'type': 'Tool', 'version': ''}

                    xxx = xit["string"].replace("Tool: ", "")
                    if not xxx in xapk_tool:
                        xapk_tool.add(xxx)

            elif xit["type"] == "APK Tool":
                # {'info': '', 'name': 'ApkEditor', 'string': 'APK Tool: ApkEditor', 'type': 'APK Tool', 'version': ''}
                # {'info': '', 'name': 'AntiLVL', 'string': 'APK Tool: AntiLVL(1.1.1)', 'type': 'APK Tool', 'version': '1.1.1'}
                # {'info': '', 'name': 'dex2jar', 'string': 'APK Tool: dex2jar', 'type': 'APK Tool', 'version': ''}
                xxx = xit["string"].replace("Tool: ", "")
                if not xxx in xapk_apk_tool:
                    xapk_apk_tool.add(xxx)

            elif xit["type"] == "Language":
                # {'info': '', 'name': 'Java', 'string': 'Language: Java', 'type': 'Language', 'version': ''}
                # {'info': '', 'name': 'BASIC', 'string': 'Language: BASIC', 'type': 'Language', 'version': ''}
                # {'info': '', 'name': 'Kotlin', 'string': 'Language: Kotlin', 'type': 'Language', 'version': ''}
                xxx = xit["string"].replace("Language: ", "")
                if not xxx in xapk_lang:
                    xapk_lang.add(xxx)

            elif xit["type"] == "Sign tool":
                # {'info': '', 'name': 'Android SignApk', 'string': 'Sign tool: Android SignApk(1.0)', 'type': 'Sign tool', 'version': '1.0'}
                # {'info': '', 'name': 'd2j-apk-sign', 'string': 'Sign tool: d2j-apk-sign(0.0.0.4)', 'type': 'Sign tool', 'version': '0.0.0.4'}
                # {'info': '', 'name': 'COMEX SignApk', 'string': 'Sign tool: COMEX SignApk(1.0)', 'type': 'Sign tool', 'version': '1.0'}
                # {'info': '', 'name': 'ApkSigner', 'string': 'Sign tool: ApkSigner', 'type': 'Sign tool', 'version': ''}
                # {'info': '', 'name': 'APK Signature Scheme', 'string': 'Sign tool: APK Signature Scheme(v2)', 'type': 'Sign tool', 'version': 'v2'}
                # {'info': '', 'name': 'dotools sign apk', 'string': 'Sign tool: dotools sign apk(1.0)', 'type': 'Sign tool', 'version': '1.0'}
                # {'info': '', 'name': 'signupdate', 'string': 'Sign tool: signupdate(1.0)', 'type': 'Sign tool', 'version': '1.0'}
                # {'info': '', 'name': 'tiny-sign', 'string': 'Sign tool: tiny-sign(0.0)', 'type': 'Sign tool', 'version': '0.0'}
                # {'info': '', 'name': 'Android apksigner', 'string': 'Sign tool: Android apksigner(0.0.0)', 'type': 'Sign tool', 'version': '0.0.0'}
                # {'info': '', 'name': 'Baidu Signature platform', 'string': 'Sign tool: Baidu Signature platform(1.0)', 'type': 'Sign tool', 'version': '1.0'}
                # {'info': '', 'name': 'signatory', 'string': 'Sign tool: signatory(1.0)', 'type': 'Sign tool', 'version': '1.0'}
                # {'info': '', 'name': 'apk-signer', 'string': 'Sign tool: apk-signer(5.2.1 (#36))', 'type': 'Sign tool', 'version': '5.2.1 (#36)'}
                # {'info': '', 'name': 'PseudoApkSigner', 'string': 'Sign tool: PseudoApkSigner(1.6 (AntiSplit-G2))', 'type': 'Sign tool', 'version': '1.6 (AntiSplit-G2)'}
                xapk_sigtool = xit["string"].replace("Sign tool: ", "").strip()

            elif xit["type"] == "Library":
                # {'info': '', 'name': 'Basic4Android', 'string': 'Library: Basic4Android', 'type': 'Library', 'version': ''}
                # {'info': '', 'name': 'Unity', 'string': 'Library: Unity', 'type': 'Library', 'version': ''}
                # {'info': '', 'name': 'Unicom SDK', 'string': 'Library: Unicom SDK', 'type': 'Library', 'version': ''}
                # {'info': '', 'name': 'IL2CPP', 'string': 'Library: IL2CPP', 'type': 'Library', 'version': ''}
                # {'info': '', 'name': 'Android Jetpack', 'string': 'Library: Android Jetpack(1.0.0-rc01)', 'type': 'Library', 'version': '1.0.0-rc01'}
                # {'info': '', 'name': 'SandHook', 'string': 'Library: SandHook', 'type': 'Library', 'version': ''}

                xxx = xit["string"].replace("Library: ", "")
                if not xxx in xapk_library:
                    xapk_library.add(xxx)

            elif xit["type"] == "Format":
                # {'info': '37888 records', 'name': 'ZIP', 'string': 'Format: ZIP(1.0)[37888 records]', 'type': 'Format', 'version': '1.0'}
                xapk_format = xit["string"].replace("Format: ", "").strip()

            elif xit["type"] == "Protector":
                # {'info': '', 'name': 'Bangcle Protection', 'string': 'Protector: Bangcle Protection', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'DexGuard', 'string': 'Protector: DexGuard', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'PangXie', 'string': 'Protector: PangXie', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'SecShell', 'string': 'Protector: SecShell', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'iJiami', 'string': 'Protector: iJiami', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'APKProtect', 'string': 'Protector: APKProtect', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Mobile Tencent Protect', 'string': 'Protector: Mobile Tencent Protect(0.0.3)', 'type': 'Protector', 'version': '0.0.3'}
                # {'info': '', 'name': 'jiagu', 'string': 'Protector: jiagu', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'DexProtector', 'string': 'Protector: DexProtector', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Baidu Protection', 'string': 'Protector: Baidu Protection', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'SecNeo', 'string': 'Protector: SecNeo', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Nagapt Protection', 'string': 'Protector: Nagapt Protection', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Alibaba Protection', 'string': 'Protector: Alibaba Protection', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Qihoo 360 Protection', 'string': 'Protector: Qihoo 360 Protection', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'NQ Shield', 'string': 'Protector: NQ Shield', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'AppSolid', 'string': 'Protector: AppSolid', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Medusah', 'string': 'Protector: Medusah', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Tencent Protection', 'string': 'Protector: Tencent Protection', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'yidun', 'string': 'Protector: yidun', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Hdus-Wjus', 'string': 'Protector: Hdus-Wjus', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'ApkProtector', 'string': 'Protector: ApkProtector', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'DxShield', 'string': 'Protector: DxShield', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'qdbh', 'string': 'Protector: qdbh', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Kiro', 'string': 'Protector: Kiro', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'LIAPP', 'string': 'Protector: LIAPP', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Proguard', 'string': 'Protector: Proguard', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'VDog', 'string': 'Protector: VDog', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'AppGuard', 'string': 'Protector: AppGuard', 'type': 'Protector', 'version': ''}
                # {'info': '', 'name': 'Tencent Legu', 'string': 'Protector: Tencent Legu(4.1.0.27)', 'type': 'Protector', 'version': '4.1.0.27'}
                xapk_protector = xit["string"].replace("Protector: ", "").strip()

            elif xit["type"] == "Source code":
                # {'info': '', 'name': 'HTML', 'string': 'Source code: HTML', 'type': 'Source code', 'version': ''}
                pass

            elif xit["type"] == "Unknown":
                # {'info': '', 'name': 'Unknown', 'string': 'Unknown: Unknown', 'type': 'Unknown', 'version': ''}
                pass

            else:
                print(jdata)
                print(xit)
                raise AssertionError("ERROR: missed XAPKDC info field")

            if not xit["name"] in keep_names:
                print(jdata)
                print(xit)
                raise AssertionError("ERROR: missed INFO element")

    xapk_tool = sorted(xapk_tool)
    xapk_apk_tool = sorted(xapk_apk_tool)
    xapk_lang = sorted(xapk_lang)
    xapk_library = sorted(xapk_library)

    if xapk_format:
        if "ZIP(" in xapk_format:
            # [[], [], [], [], [], [], [], [], ['ZIP(2.0)[53504 records]'], []]
            xapk_status = "ERROR"
        else:
            xapk_status = "UNKNOWN"
    else:
        if "Android SDK(API " in xapk_andro_sdk:
            # 'Android(4.3.1)', 'JVM', 'Android SDK(API 18)', ['JDK(1.6.0_45)'], [], ['Java'], [], [], '', '']
            # 'Android(6.2.0)', '', 'Android SDK(API 24)', [], [], ['Java'], [], [], '', '']
            xapk_status = "OK"
        else:
            # [[], ['JVM'], [], ['JDK(1.7.0_75)'], [], ['Java'], [], [], [], []]
            # [[], ['JVM'], [], [], [], ['Java'], [], [], [], ['DexGuard(6.0.26)']]
            xapk_status = "PARTIAL"

    if xapk_protector:
        xapk_protected = "True"
    else:
        xapk_protected = "False"

    res = [
           xapk_status,
           xapk_protected,
           xapk_os,
           xapk_vm,
           xapk_andro_sdk,
           xapk_tool,
           xapk_apk_tool,
           xapk_lang,
           xapk_sigtool,
           xapk_library,
           xapk_format,
           xapk_protector,
          ]
    return res


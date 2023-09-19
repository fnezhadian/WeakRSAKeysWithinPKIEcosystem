# -*- coding: utf-8 -*-
import hashlib
import io
import os
import json
import subprocess
import os
import os.path
import sys
import time
import warnings
from collections import OrderedDict

import base64
from pathlib import Path

from APKParser import apk_file_extractor_v3
from Helper import file_helper
from apk_parse3.apk import APK



sdk_signer_path = "/media/user01/WORK_2/Android/Android/Sdk/build-tools/33.0.1/apksigner"
sdk_zipalign_path = "/media/user01/WORK_2/Android/Android/Sdk/build-tools/33.0.1/zipalign"
sdk_aapt2_path = "/media/user01/WORK_2/Android/Android/Sdk/build-tools/33.0.1/aapt2"


def parse_file(file_path):
    result = OrderedDict()
    content = io.open(file_path, 'r', encoding='utf-8', errors="backslashreplace").read()
    if os.path.exists(file_path):
        result['file_parse_time'] = str(int(time.time()))
        file_type_magic = file_helper.get_type_magic_linux(file_path)
        result['file_type_magic'] = file_type_magic
        file_mod_time = file_helper.get_mod_time(file_path)
        result['file_mod_time'] = file_mod_time
        file_size = file_helper.get_size(file_path)
        result['file_size'] = file_size
        file_mime_type = file_helper.get_mime_type_magic(content)
        result['file_mime_type'] = file_mime_type
        md5, sha1, sha256 = file_helper.get_file_hash_v2(file_path)
        result['md5'] = md5
        result['sha1'] = sha1
        result['sha256'] = sha256
        file_name_base64 = file_helper.get_file_name_base64(file_path)
        result['file_name_base64'] = file_name_base64
        file_safe_path = file_helper.get_safe_path(file_path)
        result['file_safe_path'] = file_safe_path
    return result


def sdk_test_zipalign(filename):
    command = [sdk_zipalign_path,
               "-c",
               "-p",
               "-v",
               "4",
               filename, ]
    try:
        ret = subprocess.check_output(command,
                                      stderr=subprocess.STDOUT,
                                      shell=False)
        return_code = 0
    except subprocess.CalledProcessError as ex:
        ret = ex.output
        return_code = ex.returncode

    count_ok = 0
    count_ok_comp = 0
    count_bad = 0
    aligned = False
    status = ""
    if return_code == 0:
        status = "OK"
    else:
        status = "ERR"
    if status == "ERR":
        results = [status, count_ok, count_ok_comp, count_bad, aligned]
        return results
    else:
        str_result = ret.decode('latin-1')
        xstr_result = str_result.split("\n")
        for xline in xstr_result:
            if not "Verifying alignment of" in xline:
                if xline.endswith("(OK - compressed)"):
                    count_ok_comp = count_ok_comp + 1
                elif xline.endswith("(OK)"):
                    count_ok = count_ok + 1
                elif xline.endswith("(BAD - "):
                    count_bad = count_bad + 1
                elif xline == "Verification successful":
                    aligned = True
        results = [status, count_ok, count_ok_comp, count_bad, aligned]
        return results


def test_archive_7z(filename):
    command = ["7z", "t", filename, ]
    try:
        ret = subprocess.check_output(command,
                                      stderr=subprocess.STDOUT,
                                      shell=False)
        return_code = 0
    except subprocess.CalledProcessError as ex:
        ret = ex.output
        return_code = ex.returncode
    str_result = ret.decode('utf-8')
    xstr_result = str_result.split("\n")
    z_type = ""
    status = ""
    if return_code == 0:
        status = "OK"
    elif return_code == 1:
        status = "WARN"
    elif return_code == 2:
        status = "ERR"
    elif return_code == 7:
        status = "CLI"
    elif return_code == 8:
        status = "MEM"
    elif return_code == 255:
        status = "USER"
    for line in xstr_result:
        if "Type = " in line:
            z_type = line.split("Type =")[1].split("\n")[0].strip()
    result = [z_type, status]
    return result


def test_archive_zip(filename):
    command = ["zip", "-T", filename, ]
    try:
        ret = subprocess.check_output(command,
                                      stderr=subprocess.STDOUT,
                                      shell=False)
        return_code = 0
    except subprocess.CalledProcessError as ex:
        ret = ex.output
        return_code = ex.returncode

    str_result = ret.decode('utf-8')
    xstr_result = str_result.split("\n")

    status = ""
    for item in xstr_result:
        if item.startswith("test of"):
            status = item.split(".apk")[1].strip()

    z_valid = ""
    if return_code == 0:
        z_valid = "OK"
    else:
        z_valid = "ERR"

    result = [status, z_valid]
    return result


def run_apksigner(filename):
    # requires Android SDK studio
    # command = [sdk_dir_path + "/build-tools/" + sdk_version + "/apksigner",
    command = [sdk_signer_path,
               "verify",
               "--verbose",
               "--max-sdk-version", "34",
               filename, ]

    try:
        ret = subprocess.check_output(command,
                                      stderr=subprocess.STDOUT,
                                      shell=False)

        return_code = 0
    except subprocess.CalledProcessError as ex:
        ret = ex.output
        return_code = ex.returncode

    str_result = ret.decode('utf-8')
    xstr_result = str_result.split("\n")

    status = ""
    if return_code == 0:
        status = "OK"
    else:
        status = "ERR"

    sig_v1 = "0"
    sig_v2 = "0"
    sig_v3 = "0"
    sig_v31 = "0"
    sig_v4 = "0"
    sourcestamp = "0"
    signers = "0"
    warnings = dict()
    failed = False

    # ANDROID VERSIONS --> https://en.wikipedia.org/wiki/Android_version_history

    # APK Signature Scheme v2 support was added in Android API Level 24
    # Android 7.0 introduces APK Signature Scheme v2 --> API 24 to API 27 --> 2016
    # APK key rotation from NOUGAT 7.0 – 7.1.2 --> API 25 --> 2016

    # Android 9 adds support for APK Signature Scheme v3 --> API 28 to API 29 --> 2018, 2019
    #  If your app's minSdkVersion is 27 or lower, use an old signing certificate
    # to sign your app in addition to the new signature.

    # Android 11 adds support for APK Signature Scheme v4. --> API 30 --> 2020
    # This scheme produces a new kind of signature in a separate file
    # (apk-name.apk.idsig) but is otherwise similar to v2 and v3.

    # Android 13 adds support for APK Signature Scheme v3.1 --> API 33 --> 2022
    # This scheme addresses some of the known issues with APK Signature Scheme v3 regarding rotation.
    # https://developer.android.com/about/versions/13/features

    # Exception in thread "main" java.lang.IllegalArgumentException: minSdkVersion from APK (16) > maxSdkVersion (10)

    # Verifies
    # Verified using v1 scheme (JAR signing): true
    # Verified using v2 scheme (APK Signature Scheme v2): true
    # Verified using v3 scheme (APK Signature Scheme v3): false
    # Verified using v3.1 scheme (APK Signature Scheme v3.1): false
    # Verified using v4 scheme (APK Signature Scheme v4): false
    # Verified for SourceStamp: false
    # Number of signers: 1

    for xline in xstr_result:
        # Verified using v1 scheme (JAR signing): true
        if "Verified using v1 scheme" in xline:
            sig_v1 = xline.split("):")[1].strip()

        # Android 7.0 introduces APK Signature Scheme v2
        # Verified using v2 scheme (APK Signature Scheme v2): true
        elif "Verified using v2 scheme" in xline:
            sig_v2 = xline.split("):")[1].strip()

        # Verified using v3.1 scheme (APK Signature Scheme v3.1): false
        elif "Verified using v3.1 scheme" in xline:
            sig_v31 = xline.split("):")[1].strip()

        # Verified using v3 scheme (APK Signature Scheme v3): true
        elif "Verified using v3 scheme" in xline:
            sig_v3 = xline.split("):")[1].strip()

        # Verified using v4 scheme (APK Signature Scheme v4): false
        elif "Verified using v4 scheme" in xline:
            sig_v4 = xline.split("):")[1].strip()

        elif "Number of signers:" in xline:
            # Number of signers: 1
            try:
                int(xline.split(":")[1].strip())
                signers = xline.split(":")[1].strip()
            except:
                print(xline)
                # pass
                raise

        elif "Verified for SourceStamp:" in xline:
            # Verified for SourceStamp: false
            # Verified for SourceStamp: true
            sourcestamp = xline.split(":")[1].strip()

        elif xline.startswith("WARNING:"):
            if "not protected by signature." in xline:
                xfile = xline.split("not protected by signature.")[0].split(":")[1].strip()

                if xfile in warnings:
                    warnings[xfile] = warnings[xfile] + 1
                else:
                    warnings[xfile] = 1

        elif "DOES NOT VERIFY" in xline:
            failed = True

        # ERROR: APK Signature Scheme v2 signer #1: Malformed additional attribute #1
        # WARNING: APK Signature Scheme v2 signer #1: Unknown signature algorithm: 0x421
        if xline.startswith("ERROR:") or xline.startswith("WARNING:"):
            if "APK Signature Scheme v1" in xline:
                if "Malformed" in xline:
                    sig_v1 = "Malformed"
                elif "Unknown" in xline:
                    sig_v1 = "Unknown"
            elif "APK Signature Scheme v2" in xline:
                if "Malformed" in xline:
                    sig_v2 = "Malformed"
                elif "Unknown" in xline:
                    sig_v2 = "Unknown"
            elif "APK Signature Scheme v3.1" in xline:
                if "Malformed" in xline:
                    sig_v31 = "Malformed"
                elif "Unknown" in xline:
                    sig_v31 = "Unknown"
            elif "APK Signature Scheme v3" in xline:
                if "Malformed" in xline:
                    sig_v3 = "Malformed"
                elif "Unknown" in xline:
                    sig_v3 = "Unknown"
            elif "APK Signature Scheme v4" in xline:
                if "Malformed" in xline:
                    sig_v4 = "Malformed"
                elif "Unknown" in xline:
                    sig_v4 = "Unknown"
            # WARNING: JAR signer GOOGPLAY.RSA: JAR signature META-INF/GOOGPLAY.SF
            # references unknown APK signature scheme ID: 3
            elif "unknown APK signature scheme ID: 3" in xline:
                sig_v3 = "true"
            elif "unknown APK signature scheme ID: 3.1" in xline:
                sig_v31 = "true"
            elif "unknown APK signature scheme ID: 4" in xline:
                sig_v4 = "true"
            # else:
            #    print(xline)
            #    raise

    num_warnings = len(warnings)

    if not (status == "ERR"):
        if not (failed == True):
            if sig_v1 == sig_v2 == sig_v3 == sig_v31 == sig_v4 == signers == sourcestamp == "":
                print(filename)
                print(status)
                print(repr(xstr_result))
                raise AssertionError("ERROR: apksigner results are empty")

    results = [sig_v1, sig_v2, sig_v3, sig_v31, sig_v4, sourcestamp, signers, num_warnings, status, failed, warnings]
    return results


def parse_aapt2_log(filename):
    # https://android.googlesource.com/platform/frameworks/base/+/master/tools/aapt2/dump/DumpManifest.cpp

    # /home/user01/Android/Sdk/build-tools/32.1.0-rc1/aapt2 dump badging <..apk..>
    # requires Android SDK studio
    # command = [sdk_dir_path + "/build-tools/" + sdk_version + "/aapt2",
    command = [sdk_aapt2_path,
               "dump",
               "badging",
               filename, ]

    try:
        ret = subprocess.check_output(command,
                                      stderr=subprocess.STDOUT,
                                      shell=False)

        return_code = 0
    except subprocess.CalledProcessError as ex:
        ret = ex.output
        return_code = ex.returncode

    str_result = ret.decode('utf-8')
    xstr_result = str_result.split("\n")

    status = ""
    if return_code == 0:
        status = "OK"
    else:
        status = "ERR"

    apk_aapt2_status = str(status)
    apk_name = ""
    apk_versionCode = ""
    apk_versionName = ""
    apk_platformBuildVersionName = ""
    apk_platformBuildVersionCode = ""
    apk_compileSdkVersion = ""
    apk_compileSdkVersionCodename = ""
    apk_sdkVersion = ""
    apk_targetSdkVersion = ""
    apk_maxSdkVersion = ""
    apk_application_label = ""
    install_location = ""
    supports_any_density = ""
    uses_gl_es = ""
    requires_smallest_width = ""
    supports_gl_texture = ""
    app_default_label = ""
    app_default_icon = ""
    app_default_banner = ""
    compatible_width_limit = ""
    original_package = ""
    largest_width_limit = ""
    application_debuggable = "false"
    application_isgame = "false"
    application_test_only = ""

    pix_icon = OrderedDict()

    static_library = []
    uses_static_library = []
    uses_typed_package = []
    meta_data = []
    package_verifier = []
    uses_package = []

    library_used = []
    library_not_required = []
    provide_components = []
    supports_screens = []

    locales = []
    locale_labes = dict()

    launchable_activity = dict()
    leanback_launchable_activity = dict()

    native_code = []
    native_code_alt = []
    uses_native_library_not_required = []

    app_user_permissions = []
    app_user_permissions_23 = []
    app_user_permissions_implied = []
    optional_permissions = []
    app_user_permissions_TOTAL = []

    app_user_feature = []
    app_user_feature_23 = []
    app_user_feature_implied = []
    app_user_feature_implied_23 = []
    app_user_feature_not_required = []
    app_user_feature_TOTAL = []

    uses_config = ""

    file_reference_no_path = dict()
    invalid_types = []
    compatible_screens = []

    for xline in xstr_result:

        xline = xline.strip()
        if xline:

            if xline.strip().startswith("sdkVersion:'"):
                apk_sdkVersion = xline.strip().split(":")[1].replace("'", "").strip()

            elif xline.strip().startswith("targetSdkVersion:'"):
                targetSdkVersion = xline.strip().split(":")[1].replace("'", "").strip()

            elif xline.strip().startswith("uses-permission: name='"):
                # <uses-permission> applies to all SDKs
                xp = xline.strip().replace("uses-permission: name='", "").replace("'", "")
                if not xp in app_user_permissions:
                    app_user_permissions.append(xp)

            elif xline.strip().startswith("package: name='"):
                # package: name='com.xvideostudio.videoeditor' versionCode='1727' versionName='9.5.7 rc' platformBuildVersionName='6.0-2438415' platformBuildVersionCode='23' compileSdkVersion='23' compileSdkVersionCodename='6.0-2438415'
                # package: name=' com.wphm.englishkaoyan.activit' versionCode='20131121' versionName='20131121'
                # package: name='de.mobinauten.smsspy' versionCode='9' versionName='1.6.0 Within the functionality 'hiding/deleting the incoming SMS on the located device' some bugs repaired'

                zxline = str(xline).strip()
                if "package: name='" in zxline:
                    zxline = zxline.replace("package: name='", "name='")
                if "' versionCode='" in zxline:
                    zxline = zxline.replace("' versionCode='", "'|#@*~!_versionCode='")
                if "' versionName='" in zxline:
                    zxline = zxline.replace("' versionName='", "'|#@*~!_versionName='")
                if "' platformBuildVersionName='" in zxline:
                    zxline = zxline.replace("' platformBuildVersionName='", "'|#@*~!_platformBuildVersionName='")
                if "' platformBuildVersionCode='" in zxline:
                    zxline = zxline.replace("' platformBuildVersionCode='", "'|#@*~!_platformBuildVersionCode='")
                if "' compileSdkVersion='" in zxline:
                    zxline = zxline.replace("' compileSdkVersion='", "'|#@*~!_compileSdkVersion='")
                if "' compileSdkVersionCodename='" in zxline:
                    zxline = zxline.replace("' compileSdkVersionCodename='", "'|#@*~!_compileSdkVersionCodename='")
                xls = zxline.split("|#@*~!_")

                # print(xls)
                # sys.exit()

                xls = [i.strip(' ') for i in xls]
                for xl in xls:
                    if xl:
                        if xl.startswith("name="):
                            apk_name = xl.replace("name='", "")[:-1]
                        elif xl.startswith("versionCode="):
                            apk_versionCode = xl.replace("versionCode='", "")[:-1]
                        elif xl.startswith("versionName="):
                            apk_versionName = xl.replace("versionName='", "")[:-1]
                        elif xl.startswith("platformBuildVersionName="):
                            apk_platformBuildVersionName = xl.replace("platformBuildVersionName='", "")[:-1]
                        elif xl.startswith("platformBuildVersionCode="):
                            apk_platformBuildVersionCode = xl.replace("platformBuildVersionCode='", "")[:-1]
                        elif xl.startswith("compileSdkVersion="):
                            apk_compileSdkVersion = xl.replace("compileSdkVersion='", "")[:-1]
                        elif xl.startswith("compileSdkVersionCodename="):
                            apk_compileSdkVersionCodename = xl.replace("compileSdkVersionCodename='", "")[:-1]
                        else:
                            print("$$$$$$$$$$$$$$$$$$$$$$$")
                            print(filename)
                            print("++++++++++")
                            print(xstr_result)
                            print("++++++++++")
                            print(xline)
                            print(xl)
                            raise AssertionError("ERROR: unkown element")

                # print(xline)
                # print(zxline)
                # print(xls)
                # print(apk_name)
                # print(apk_versionCode)
                # print(apk_versionName)
                # print(apk_platformBuildVersionName)
                # print(apk_platformBuildVersionCode)
                # print(apk_compileSdkVersion)
                # print(apk_compileSdkVersionCodename)
                # sys.exit()

                """                
                xls = xline.strip().replace("package: name='", "name='").split("'")
                xls = [i.strip(' ') for i in xls]
                for xl in xls:
                    if '=' in xl:
                        if xl.startswith("name="):
                            apk_name = xls[xls.index(xl) + 1]
                        elif xl.startswith("versionCode="):
                            apk_versionCode = xls[xls.index(xl) + 1]
                        elif xl.startswith("versionName="):
                            apk_versionName = xls[xls.index(xl) + 1]
                        elif xl.startswith("platformBuildVersionName="):
                            apk_platformBuildVersionName = xls[xls.index(xl) + 1]
                        elif xl.startswith("platformBuildVersionCode="):
                            apk_platformBuildVersionCode = xls[xls.index(xl) + 1]
                        elif xl.startswith("compileSdkVersion="):
                            apk_compileSdkVersion = xls[xls.index(xl) + 1]
                        elif xl.startswith("compileSdkVersionCodename="):
                            apk_compileSdkVersionCodename = xls[xls.index(xl) + 1]
                        else:
                                    print("$$$$$$$$$$$$$$$$$$$$$$$")
                                    print(filename)
                                    print("++++++++++")
                                    print(xstr_result)
                                    print("++++++++++")
                                    print(xline)
                                    print(xl)
                                    raise AssertionError("ERROR: unkown element")
                """

            elif xline.strip().startswith("application-label:'"):
                apk_application_label = xline.strip().replace("application-label:'", ":'").split(":")[1].replace("'",
                                                                                                                 "").strip()

            elif xline.strip().startswith("application-icon-"):
                xden = xline.strip().replace("application-icon-", "").split(":")[0]
                xicon = xline.strip().split(":")[1].replace("'", "").strip()
                pix_icon[xden] = xicon

            elif xline.strip().startswith("uses-library-not-required:'"):
                # uses-library-not-required:'com.sec.android.app.multiwindow'
                # uses-library-not-required:'org.apache.http.legacy'
                xlib = xline.split(":")[1].replace("'", "").strip()
                if not xlib in library_not_required:
                    library_not_required.append(xlib)

            elif xline.strip().startswith("install-location:'"):
                install_location = xline.split(":")[1].replace("'", "").strip()

            elif xline.strip().startswith("provides-component:'"):
                xcomp = xline.split(":")[1].replace("'", "").strip()
                if not xcomp in provide_components:
                    provide_components.append(xcomp)

            elif xline.strip().startswith("densities: '"):
                xdens = xline.split(":")[1].strip().split(" ")
                for xdns in xdens:
                    xdns = xdns.replace("'", "").strip()
                    if not xdns in pix_icon:
                        pix_icon[xdns] = ""

            elif xline.strip().startswith("supports-screens: '"):
                xscrs = xline.split(":")[1].strip().split(" ")
                for xscr in xscrs:
                    xscr = xscr.replace("'", "").strip()
                    if not xscr in supports_screens:
                        supports_screens.append(xscr)

            elif xline.strip().startswith("supports-any-density: '"):
                # supports-any-density: 'true'
                supports_any_density = xline.split(":")[1].replace("'", "").strip()

            elif xline.strip().startswith("locales: '"):
                xlocs = xline.split(":")[1].strip().split(" ")
                for xloc in xlocs:
                    xloc = xloc.replace("'", "").strip()
                    if not xloc in locales:
                        locales.append(xloc)

            elif xline.strip().startswith("application-label-"):
                xclo_named = xline.split(":")[0].replace("'", "").strip()
                xclo_label = xline.split(":")[1].replace("'", "").strip()
                locale_labes[xclo_named] = xclo_label

            elif xline.strip().startswith("launchable-activity: name='"):
                xlants = xline.replace("name=", "|").replace("label=", "|").replace("icon=", "|").split("|")
                launchable_activity["name"] = xlants[1].replace("'", "").strip()
                launchable_activity["label"] = xlants[2].replace("'", "").strip()
                launchable_activity["icon"] = xlants[3].replace("'", "").strip()

            elif xline.strip().startswith("leanback-launchable-activity: name='"):
                xlants = xline.replace("name=", "|").replace("label=", "|").replace("icon=", "|").replace("banner=",
                                                                                                          "|").split(
                    "|")
                launchable_activity["name"] = xlants[1].replace("'", "").strip()
                launchable_activity["label"] = xlants[2].replace("'", "").strip()
                launchable_activity["icon"] = xlants[3].replace("'", "").strip()
                launchable_activity["banner"] = xlants[4].replace("'", "").strip()

            elif xline.strip().startswith("alt-native-code: '"):
                xalncs = xline.split(":")[1].strip().split(" ")
                for xalnc in xalncs:
                    xalnc = xalnc.replace("'", "").strip()
                    if not xalnc in native_code_alt:
                        native_code_alt.append(xalnc)

            elif xline.strip().startswith("native-code: '"):
                xnccs = xline.split(":")[1].strip().split(" ")
                for xncc in xnccs:
                    xncc = xncc.replace("'", "").strip()
                    if not xncc in native_code:
                        native_code.append(xncc)

            elif xline.strip().startswith("uses-gl-es: '"):
                uses_gl_es = xline.split(":")[1].replace("'", "").strip()

            elif xline.strip().startswith("optional-permission: name='"):
                xopperm = xline.split(":")[1].replace("'", "")
                if not xopperm in optional_permissions:
                    optional_permissions.append(xopperm)

            elif xline.strip().startswith("uses-permission-sdk-23: name='"):
                # <uses-permission-sdk-23> will apply the permission only to SDK 23+
                xp = xline.strip().replace("uses-permission-sdk-23: name='", "").replace("'", "")
                if not xp in app_user_permissions_23:
                    app_user_permissions_23.append(xp)

            elif xline.strip().startswith("uses-implied-permission: name='"):
                ximplp = xline.split(":")[1].split("=")[1].split("'")[1].strip()
                if not ximplp in app_user_permissions_implied:
                    app_user_permissions_implied.append(ximplp)

            elif xline.strip().startswith("uses-feature-sdk-23: name='"):
                xp = xline.strip().replace("uses-feature-sdk-23: name='", "").replace("'", "")
                if not xp in app_user_feature_23:
                    app_user_feature_23.append(xp)

            elif xline.strip().startswith("uses-feature: name='"):
                xp = xline.strip().replace("uses-feature: name='", "").replace("'", "")
                if not xp in app_user_feature:
                    app_user_feature.append(xp)

            elif xline.strip().startswith("uses-implied-feature: name='"):
                xp = xline.strip().split(":")[1].split("=")[1].split("'")[1].strip()
                if not xp in app_user_feature_implied:
                    app_user_feature_implied.append(xp)

            elif xline.strip().startswith("uses-implied-feature-sdk-23: name='"):
                xp = xline.strip().split(":")[1].split("=")[1].split("'")[1].strip()
                if not xp in app_user_feature_implied_23:
                    app_user_feature_implied_23.append(xp)

            elif xline.strip().startswith("uses-feature-not-required: name='"):
                xp = xline.strip().replace("uses-feature-not-required: name='", "").replace("'", "")
                if not xp in app_user_feature_not_required:
                    app_user_feature_not_required.append(xp)

            elif "but no such path exists" in xline.strip():
                xxwar = xline.strip().lstrip("warn: resource ").replace("' is a file reference to '", "|")
                xxwar = xxwar.replace(" for config '", "|").replace("' but no such path exists.", "")
                xss = xxwar.split("|")[0]
                xpp = xxwar.split("|")[2]
                file_reference_no_path[xss] = xpp

            elif ": warn: invalid type name '" in xline.strip():
                # invalid type name 'istring' for type with ID .
                xxi = xline.strip().split(": warn: invalid type name '")[1]
                xxis = "invalid type name '" + xxi
                if not xxis in invalid_types:
                    invalid_types.append(xxis)

            elif xline.strip().startswith("uses-configuration: "):
                uses_config = xline.strip().split(":")[1]

            elif xline.strip().startswith("requires-smallest-width:'"):
                requires_smallest_width = xline.strip().replace("requires-smallest-width:'", "").replace("'", "")

            elif xline.strip().startswith("uses-library:'"):
                #  4 uses-library:'com.google.android.maps'
                # 25 uses-library:'android.test.runner'
                xlib = xline.split(":")[1].replace("'", "").strip()
                if not xlib in library_used:
                    library_used.append(xlib)

            elif xline.strip().startswith("supports-gl-texture:'"):
                #  4 supports-gl-texture:'GL_OES_compressed_paletted_texture'
                # 16 supports-gl-texture:'GL_OES_compressed_ETC1_RGB8_texture'
                supports_gl_texture = xline.strip().replace("supports-gl-texture:'", "").replace("'", "")

            elif xline.strip().startswith("application: label='"):
                # application: label='VPNBaz' icon='res/mipmap-mdpi-v4/ic_launcher.png'
                # application: label='MX Player Pro' icon='res/mipmap-anydpi-v26/icon.xml' banner='res/drawable-xhdpi/banner_pro.png'
                xappli = xline.split(":")[1].replace("label=", "").replace("icon=", "").replace("banner=", "")
                if len(xappli) == 3:
                    app_default_label = xappli[1].replace("'", "")
                    app_default_icon = xappli[2].replace("'", "")
                    app_default_banner = xappli[3].replace("'", "")
                else:
                    app_default_label = xappli[1].replace("'", "")
                    app_default_icon = xappli[2].replace("'", "")
                    app_default_banner = ""

            elif xline.strip().startswith("compatible-screens:"):
                xfcs = xline.strip().split(":")[1].strip()
                if xfcs:
                    compatible_screens = xfcs.replace("'", "").split(",")
                else:
                    compatible_screens = []

            elif xline.strip().startswith("uses-native-library-not-required:'"):
                # 1 uses-native-library-not-required:'libOpenCL-pixel.so'
                # 1 uses-native-library-not-required:'libOpenCL.so'
                xlib = xline.split(":")[1].replace("'", "").strip()
                if not xlib in uses_native_library_not_required:
                    uses_native_library_not_required.append(xlib)

            elif xline.strip().startswith("compatible-width-limit:'"):
                #  2 compatible-width-limit:'1000'
                compatible_width_limit = xline.strip().replace("compatible-width-limit:'", "").replace("'", "")

            elif xline.strip().startswith("original-package:'"):
                # 1 original-package:'com.android.misoundrecorder'
                # 1 original-package:'com.jb.gosms'
                original_package = xline.strip().replace("original-package:'", "").replace("'", "")

            elif xline.strip().startswith("largest-width-limit:'"):
                # 1 largest-width-limit:'600'
                largest_width_limit = xline.strip().replace("largest-width-limit:'", "").replace("'", "")

            elif xline.strip().startswith("maxSdkVersion:'"):
                # 1 largest-width-limit:'600'
                apk_maxSdkVersion = xline.strip().replace("maxSdkVersion:'", "").replace("'", "")

            elif xline.strip().startswith("testOnly='"):
                # 1 largest-width-limit:'600'
                application_test_only = xline.strip().replace("testOnly='", "").replace("'", "")

            elif xline.strip().startswith("static-library: name='"):
                # "static-library: name='%s' version='%d' versionMajor='%d'\n",
                xlibx = xline.split(":")
                xlib = ":".join(xlibx[1:])
                if not xlib in static_library:
                    static_library.append(xlib)

            elif xline.strip().startswith("uses-static-library: name='"):
                # "uses-static-library: name='%s' version='%d' versionMajor='%d'",
                xlibx = xline.split(":")
                xlib = ":".join(xlibx[1:])
                if not xlib in uses_static_library:
                    uses_static_library.append(xlib)

            elif xline.strip().startswith("uses-typed-package: type='"):
                # "uses-typed-package: type='%s' name='%s' version='%d' versionMajor='%d'",
                xlibx = xline.split(":")
                xlib = ":".join(xlibx[1:])
                if not xlib in uses_typed_package:
                    uses_typed_package.append(xlib)

            elif xline.strip().startswith("meta-data: name='"):
                # printer->Print(StringPrintf("meta-data: name='%s' value='%s' resource='%s'",
                xlibx = xline.split(":")
                xlib = ":".join(xlibx[1:])
                if not xlib in meta_data:
                    meta_data.append(xlib)

            elif xline.strip().startswith("package-verifier: name='"):
                # printer->Print(StringPrintf("package-verifier: name='%s' publicKey='%s'\n",
                xlibx = xline.split(":")
                xlib = ":".join(xlibx[1:])
                if not xlib in package_verifier:
                    package_verifier.append(xlib)

            elif xline.strip().startswith("uses-package:'"):
                # printer->Print(StringPrintf("uses-package:'%s'\n", name->data()));
                xlib = xline.split(":")[1].replace("'", "").strip()
                if not xlib in uses_package:
                    uses_package.append(xlib)

            elif xline.strip() == "application-debuggable":
                application_debuggable = "true"

            elif xline.strip() == "application-isGame":
                application_isgame = "true"

            elif xline.strip() == "other-activities":
                pass
            elif xline.strip() == "other-receivers":
                pass
            elif xline.strip() == "main":
                pass
            elif xline.strip() == "other-services":
                pass
            elif xline.strip().startswith("feature-group: label='"):
                pass
            else:
                pass

                # print("$$$$$$$$$$$$$$$$$$$$$$$")
                # print(filename)
                # print("++++++++++")
                # print(xstr_result)
                # print("++++++++++")
                # print(xline)
                # raise AssertionError("ERROR: feature not parsed")

    # FIND TOTAL LIST OF PERMISSIONS USED
    app_user_permissions_TOTAL = set(
        app_user_permissions + app_user_permissions_implied + optional_permissions + app_user_permissions_23)
    app_user_permissions_TOTAL = sorted(app_user_permissions_TOTAL)

    # FIND TOTAL LIST OF FEATURES USED
    app_user_feature_TOTAL = set(
        app_user_feature + app_user_feature_implied + app_user_feature_not_required + app_user_feature_implied_23 + app_user_feature_23)
    app_user_feature_TOTAL = sorted(app_user_feature_TOTAL)

    results = OrderedDict()
    results["apk_aapt2_status"] = apk_aapt2_status
    results["apk_name"] = apk_name
    results["apk_versionCode"] = apk_versionCode
    results["apk_versionName"] = apk_versionName
    results["apk_platformBuildVersionName"] = apk_platformBuildVersionName
    results["apk_platformBuildVersionCode"] = apk_platformBuildVersionCode
    results["apk_compileSdkVersion"] = apk_compileSdkVersion
    results["apk_compileSdkVersionCodename"] = apk_compileSdkVersionCodename
    results["apk_sdkVersion"] = apk_sdkVersion
    results["apk_targetSdkVersion"] = apk_targetSdkVersion
    results["apk_maxSdkVersion"] = apk_maxSdkVersion
    results["apk_application_label"] = apk_application_label
    results["install_location"] = install_location
    results["supports_any_density"] = supports_any_density
    results["uses_gl_es"] = uses_gl_es
    results["density_icons"] = pix_icon
    results["requires_smallest_width"] = requires_smallest_width
    results["supports_gl_texture"] = supports_gl_texture  # added

    results["app_default_label"] = app_default_label
    results["app_default_icon"] = app_default_icon
    results["app_default_banner"] = app_default_banner

    results["compatible_width_limit"] = compatible_width_limit
    results["original_package"] = original_package
    results["largest_width_limit"] = largest_width_limit
    results["application_debuggable"] = application_debuggable
    results["application_isgame"] = application_isgame
    results["application_test_only"] = application_test_only

    results["supports_screens"] = supports_screens
    results["compatible_screens"] = sorted(compatible_screens)

    results["locales"] = locales
    results["locale_labels"] = locale_labes

    results["launchable_activity"] = launchable_activity
    results["leanback_launchable_activity"] = leanback_launchable_activity

    results["native_code"] = sorted(native_code)
    results["native_code_count"] = len(sorted(native_code))

    results["native_code_alt"] = sorted(native_code_alt)
    results["native_code_alt_count"] = len(sorted(native_code_alt))

    results["provide_components"] = provide_components

    results["static_library"] = sorted(static_library)
    results["uses_static_library"] = sorted(uses_static_library)
    results["uses_typed_package"] = sorted(uses_typed_package)
    results["meta_data"] = sorted(meta_data)
    results["package_verifier"] = sorted(package_verifier)
    results["uses_package"] = sorted(uses_package)

    results["library_used"] = sorted(library_used)
    results["library_not_required"] = sorted(library_not_required)
    results["uses_native_library_not_required"] = sorted(uses_native_library_not_required)

    results["app_user_permissions"] = sorted(app_user_permissions)
    results["app_user_permissions_count"] = len(sorted(app_user_permissions))
    results["app_user_permissions_23"] = sorted(app_user_permissions_23)
    results["app_user_permissions_23_count"] = len(sorted(app_user_permissions_23))
    results["app_user_permissions_implied"] = sorted(app_user_permissions_implied)
    results["app_user_permissions_implied_count"] = len(sorted(app_user_permissions_implied))
    results["optional_permissions"] = sorted(optional_permissions)
    results["optional_permissions_count"] = len(sorted(optional_permissions))
    results["app_user_permissions_TOTAL"] = sorted(app_user_permissions_TOTAL)
    results["app_user_permissions_TOTAL_count"] = len(sorted(app_user_permissions_TOTAL))

    results["app_user_feature"] = sorted(app_user_feature)
    results["app_user_feature_count"] = len(sorted(app_user_feature))
    results["app_user_feature_23"] = sorted(app_user_feature_23)
    results["app_user_feature_23_count"] = len(sorted(app_user_feature_23))
    results["app_user_feature_implied"] = sorted(app_user_feature_implied)
    results["app_user_feature_implied_count"] = len(sorted(app_user_feature_implied))
    results["app_user_feature_implied_23"] = sorted(app_user_feature_implied_23)
    results["app_user_feature_implied_23_count"] = len(sorted(app_user_feature_implied_23))
    results["app_user_feature_not_required"] = sorted(app_user_feature_not_required)
    results["app_user_feature_not_required_count"] = len(sorted(app_user_feature_not_required))
    results["app_user_feature_TOTAL"] = sorted(app_user_feature_TOTAL)
    results["app_user_feature_TOTAL_count"] = len(sorted(app_user_feature_TOTAL))

    results["file_reference_no_path"] = file_reference_no_path

    results["invalid_types"] = sorted(invalid_types)
    results["invalid_types_count"] = len(sorted(invalid_types))

    results["uses_config"] = uses_config

    # print( json.dumps(results, indent = 2) )
    # sys.exit()

    return (results)

def parse_apk_parse3(filename):
    try:
        apkf = APK(filename)
        # apkf = APK(read(test_file), raw=True)
        status = "OK"
    except Exception as e:
        status = "ERR"
        print(e)
        print(status)

    if status == "OK":
        results = OrderedDict()
        results["apk_name"] = apkf.get_filename()
        results["apk_size"] = apkf.file_size
        results["apk_md5"] = apkf.file_md5.lower()
        try:
            results["cert_fingerprint"] = apkf.get_cert_fingerprint()
        except Exception as e:
            results["cert_fingerprint"] = ""

        try:
            results["cert_sha1"] = apkf.get_cert_md5()
        except Exception as e:
            results["cert_sha1"] = ""

        try:
            results["cert_sha1"] = apkf.get_cert_sha1()
        except Exception as e:
            results["cert_sha1"] = ""

        try:
            results["cert_sha256"] = apkf.get_cert_sha256()
        except Exception as e:
            results["cert_sha256"] = ""

        try:
            results["cert_sha512"] = apkf.get_cert_sha512()
        except Exception as e:
            results["cert_sha512"] = ""

        try:
            results["androidversion"] = apkf.androidversion
        except Exception as e:
            results["androidversion"] = ""

        try:
            results["apk_package"] = apkf.package
        except Exception as e:
            results["apk_package"] = ""

        try:
            results["app_name"] = apkf.get_app_name()
        except Exception as e:
            results["app_name"] = ""

        try:
            results["get_app_icon"] = apkf.get_app_icon()
        except Exception as e:
            results["get_app_icon"] = ""

        try:
            results["apk_is_valid"] = apkf.is_valid_APK()
        except Exception as e:
            results["apk_is_valid"] = ""

        try:
            results["apk_package"] = apkf.get_package()
        except Exception as e:
            results["apk_package"] = ""

        try:
            results["androidversion_code"] = apkf.get_androidversion_code()
        except Exception as e:
            results["androidversion_code"] = ""

        try:
            results["androidversion_name"] = apkf.get_androidversion_name()
        except Exception as e:
            results["androidversion_name"] = ""

        try:
            results["max_sdk_version"] = apkf.get_max_sdk_version()
        except Exception as e:
            results["max_sdk_version"] = ""

        try:
            results["min_sdk_version"] = apkf.get_min_sdk_version()
        except Exception as e:
            results["min_sdk_version"] = ""

        try:
            results["target_sdk_version"] = apkf.get_target_sdk_version()
        except Exception as e:
            results["target_sdk_version"] = ""

        try:
            results["main_activity"] = apkf.get_main_activity()
        except Exception as e:
            results["main_activity"] = ""

        try:
            results["signature_names"] = apkf.get_signature_names()
        except Exception as e:
            results["signature_names"] = ""

        try:
            results["libraries"] = apkf.get_libraries()
        except Exception as e:
            results["libraries"] = ""

        try:
            results["activities"] = apkf.get_activities()
        except Exception as e:
            results["activities"] = ""

        try:
            results["services"] = apkf.get_services()
        except Exception as e:
            results["services"] = ""

        try:
            results["receivers"] = apkf.get_receivers()
        except Exception as e:
            results["receivers"] = ""

        try:
            results["providers"] = apkf.get_providers()
        except Exception as e:
            results["providers"] = ""

        try:
            results["permissions"] = apkf.get_permissions()
        except Exception as e:
            results["permissions"] = ""

        try:
            results["requested_permissions"] = apkf.get_requested_permissions()
        except Exception as e:
            results["requested_permissions"] = ""

        try:
            apk_files = apkf.get_files()
            results["files"] = sorted(apk_files)
        except Exception as e:
            results["files"] = ""

        try:
           android_manifest = apkf.get_android_manifest_xml().toprettyxml(indent='  ', newl='\r', encoding="utf-8")
           #android_manifest_xml = android_manifest.decode("utf-8")
           android_manifest_b64 = str(base64.b64encode(android_manifest))[2:-1]
           results["android_manifest_xml"] = str(android_manifest_b64)
           results["android_manifest_xml_sha1"] = hashlib.sha1(android_manifest).hexdigest().lower()
        except Exception as e:
           results["android_manifest_xml"] = ""
           results["android_manifest_xml_sha1"] = ""

        # print( json.dumps(results, indent = 2) )
        # sys.exit()
    else:
        results = OrderedDict()

    # print( json.dumps(results, indent = 2) )
    # sys.exit()
    return results


def parse_single_apk(apk_file_path):
    warnings.filterwarnings("ignore")

    if not os.path.exists(apk_file_path) or not os.path.isfile(apk_file_path):
        print("bad file path")
        sys.exit(0)

    # parse file
    apk_signer_res = run_apksigner(apk_file_path)

    apk_res = OrderedDict()

    # zipalign test
    # z_res = sdk_test_zipalign(apk_file_path)
    # zipalign_status = str(z_res[0])
    # zipalign_ok = str(z_res[0])
    # zipalign_ok_comp = str(z_res[1])
    # zipalign_bad = str(z_res[2])
    # zipalign_aligned = str(z_res[3])
    #
    # apk_res["zipalign"] = dict()
    # apk_res["zipalign"]["zipalign_status"] = zipalign_status
    # apk_res["zipalign"]["zipalign_ok"] = zipalign_ok
    # apk_res["zipalign"]["zipalign_ok_comp"] = zipalign_ok_comp
    # apk_res["zipalign"]["zipalign_bad"] = zipalign_bad
    # apk_res["zipalign"]["zipalign_aligned"] = zipalign_aligned

    # SDK check signatures
    apk_res["apksigner"] = dict()
    apk_res["apksigner"]["signature_v1"] = apk_signer_res[0]
    apk_res["apksigner"]["signature_v2"] = apk_signer_res[1]
    apk_res["apksigner"]["signature_v3"] = apk_signer_res[2]
    apk_res["apksigner"]["signature_v31"] = apk_signer_res[3]
    apk_res["apksigner"]["signature_v4"] = apk_signer_res[4]

    apk_res["apksigner"]["sourcestamp"] = apk_signer_res[5]
    apk_res["apksigner"]["num_signers"] = apk_signer_res[6]
    apk_res["apksigner"]["tot_warnings"] = apk_signer_res[7]
    apk_res["apksigner"]["apk_signer_test_status"] = apk_signer_res[8]
    apk_res["apksigner"]["apk_signer_test_failed"] = apk_signer_res[9]
    apk_res["apksigner"]["permission_warnings"] = [apk_signer_res[10].keys()]

    # SDK aapt2
    aapt_res = parse_aapt2_log(apk_file_path)
    apk_res["aapt2"] = aapt_res

    # GITHUB apk_parse3
    parse3 = parse_apk_parse3(apk_file_path)
    apk_res["apk_parse3"] = parse3

    return apk_res


def main(file_path, input_folder):
    output_folder = str(input_folder) + "_logs"
    maybe_keys_path = output_folder + "/maybe_keys"
    zip_dest_path = output_folder + "/unzipped"
    maybe_json_path = output_folder + "/json"

    try:
        apk_validity = parse_single_apk(file_path)
        apk_file_info_result, internal_file_info_result = apk_file_extractor_v3.main(file_path, zip_dest_path, maybe_keys_path)

        result_dict = dict()
        result_dict['apk_validity'] = apk_validity
        result_dict['apk_file_info_result'] = apk_file_info_result
        result_dict['internal_file_info_result'] = internal_file_info_result
        json_log = json.dumps(result_dict, default=str)

        apk_sha1 = apk_file_info_result['sha1']
        depth_0 = apk_sha1[0]
        depth_1 = apk_sha1[1]

        json_dir_path = "%s/%s/%s/%s" % (maybe_json_path, depth_0, depth_1, apk_sha1)
        if os.path.exists(json_dir_path):
            print('ALERT!!', json_dir_path)
        Path(json_dir_path).mkdir(parents=True, exist_ok=True)
        json_file_path = "%s/%s" % (json_dir_path, 'result.json')

        with io.open(json_file_path, 'a') as waf:
            waf.write(json_log + "\n")
    except:
        pass




if __name__ == "__main__":
    file_path = ''
    input_folder = ''
    main(file_path, input_folder)
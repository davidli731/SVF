/*  [ExtAPI.cpp] The actual database of external functions
 *  v. 005, 2008-08-08
 *------------------------------------------------------------------------------
 */

/*
 * Modified by Yulei Sui 2013
*/

#include "Util/ExtAPI.h"
#include <array>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string>

using namespace std;
using namespace SVF;

ExtAPI *ExtAPI::extAPI = nullptr;

namespace
{

  struct ei_pair
  {
    const char *n;
    ExtAPI::extf_t t;
  };

  struct ei_pair_t_map
  {
    std::string t_string_ref;
    ExtAPI::extf_t t_ref;
  };

  struct ei_pair_n_map
  {
    const char *n_ref;
  };

} // End anonymous namespace

static const ei_pair_n_map ei_pair_n_maps[] =
    {
        //The current llvm-gcc puts in the \01.
        "\01creat64",
        "\01fseeko64",
        "\01fstat64",
        "\01fstatvfs64",
        "\01ftello64",
        "\01getrlimit64",
        "\01lstat64",
        "\01open64",
        "\01stat64",
        "\01statvfs64",
        "Gpm_GetEvent",
        "Gpm_Open",
        "RAND_seed",
        "SSL_CTX_set_default_verify_paths",
        "SSL_get_error",
        "SSL_get_fd",
        "SSL_pending",
        "SSL_read",
        "SSL_set_bio",
        "SSL_set_connect_state",
        "SSL_shutdown",
        "SSL_state",
        "SSL_write",
        "Void_FreeCore",
        "X509_STORE_CTX_get_error",
        "XAllocColor",
        "XCloseDisplay",
        "XCopyArea",
        "XCreateColormap",
        "XCreatePixmap",
        "XCreateWindow",
        "XDrawPoint",
        "XDrawString",
        "XDrawText",
        "XFillRectangle",
        "XFillRectangles",
        "XFree",
        "XFreeColormap",
        "XFreeColors",
        "XFreeFont",
        "XFreeFontNames",
        "XFreeGC",
        "XFreePixmap",
        "XGetGCValues",
        "XGetGeometry",
        "XInternAtom",
        "XMapWindow",
        "XNextEvent",
        "XPutImage",
        "XQueryColor",
        "XResizeWindow",
        "XSelectInput",
        "XSendEvent",
        "XSetBackground",
        "XSetClipMask",
        "XSetClipOrigin",
        "XSetFillStyle",
        "XSetFont",
        "XSetForeground",
        "XSetFunction",
        "XSetGraphicsExposures",
        "XSetLineAttributes",
        "XSetTile",
        "XSetWMHints",
        "XSetWMNormalHints",
        "XSetWindowBackgroundPixmap",
        "XStoreName",
        "XSync",
        "XVisualIDFromVisual",
        "XWMGeometry",
        "XtAppSetFallbackResources",
        "XtCloseDisplay",
        "XtDestroyApplicationContext",
        "XtDestroyWidget",
        "_IO_getc",
        "_IO_putc",
        "__assert_fail",
        "__dn_expand",
        "__dn_skipname",
        "__res_nclose",
        "__res_ninit",
        "__res_nmkquery",
        "__res_nsend",
        "__res_query",
        "__res_querydomain",
        "__res_search",
        "__sigsetjmp",
        "_obstack_begin",
        "_obstack_memory_used",
        "_obstack_newchunk",
        "_setjmp",
        "accept",
        "access",
        "asprintf",
        "atexit",
        "atof",
        "atoi",
        "atol",
        "bind",
        "cfgetospeed",
        "cfsetispeed",
        "cfsetospeed",
        "chdir",
        "chmod",
        "chown",
        "chroot",
        "clearerr",
        "clearok",
        "closedir",
        "compress2",
        "confstr",
        "connect",
        "crc32",
        "creat",
        "creat64",
        "deflate",
        "deflateEnd",
        "deflateInit2_",
        "deflateReset",
        "delwin",
        "dladdr",
        "dlclose",
        "execl",
        "execle",
        "execlp",
        "execv",
        "execve",
        "execvp",
        "feof",
        "ferror",
        "fflush",
        "fgetc",
        "fgetpos",
        "fileno",
        "flockfile",
        "fnmatch",
        "forkpty",
        "fprintf",
        "fputc",
        "fputs",
        "fread",
        "frexp",
        "fscanf",
        "fseek",
        "fseeko",
        "fseeko64",
        "fsetpos",
        "fstat",
        "fstat64",
        "fstatfs",
        "fstatvfs64",
        "ftell",
        "ftello",
        "ftello64",
        "ftok",
        "funlockfile",
        "fwrite",
        "g_scanner_destroy",
        "g_scanner_eof",
        "g_scanner_get_next_token",
        "g_scanner_input_file",
        "g_scanner_scope_add_symbol",
        "gcry_cipher_close",
        "gcry_cipher_ctl",
        "gcry_cipher_decrypt",
        "gcry_cipher_map_name",
        "gcry_cipher_open",
        "gcry_md_close",
        "gcry_md_ctl",
        "gcry_md_get_algo",
        "gcry_md_hash_buffer",
        "gcry_md_map_name",
        "gcry_md_open",
        "gcry_md_setkey",
        "gcry_md_write",
        "gcry_mpi_add",
        "gcry_mpi_add_ui",
        "gcry_mpi_clear_highbit",
        "gcry_mpi_print",
        "getaddrinfo",
        "getc_unlocked",
        "getgroups",
        "gethostname",
        "getloadavg",
        "getopt",
        "getopt_long",
        "getopt_long_only",
        "getpeername",
        "getresgid",
        "getresuid",
        "getrlimit",
        "getrlimit64",
        "getrusage",
        "getsockname",
        "getsockopt",
        "gettimeofday",
        "gnutls_pkcs12_bag_decrypt",
        "gnutls_pkcs12_bag_deinit",
        "gnutls_pkcs12_bag_get_count",
        "gnutls_pkcs12_bag_get_type",
        "gnutls_x509_crt_deinit",
        "gnutls_x509_crt_get_dn_by_oid",
        "gnutls_x509_crt_get_key_id",
        "gnutls_x509_privkey_deinit",
        "gnutls_x509_privkey_get_key_id",
        "gzclose",
        "gzeof",
        "gzgetc",
        "gzread",
        "gzseek",
        "gztell",
        "gzwrite",
        "hstrerror",
        "iconv_close",
        "inet_addr",
        "inet_aton",
        "inet_pton",
        "inflate",
        "inflateEnd",
        "inflateInit2_",
        "inflateInit_",
        "inflateReset",
        "initgroups",
        "jpeg_CreateCompress",
        "jpeg_CreateDecompress",
        "jpeg_destroy",
        "jpeg_finish_compress",
        "jpeg_finish_decompress",
        "jpeg_read_header",
        "jpeg_read_scanlines",
        "jpeg_resync_to_restart",
        "jpeg_set_colorspace",
        "jpeg_set_defaults",
        "jpeg_set_linear_quality",
        "jpeg_set_quality",
        "jpeg_start_compress",
        "jpeg_start_decompress",
        "jpeg_write_scanlines",
        "keypad",
        "lchown",
        "link",
        "llvm.dbg",
        "llvm.stackrestore",
        "llvm.va_copy",
        "llvm.va_end",
        "llvm.va_start",
        "longjmp",
        "lstat",
        "lstat64",
        "mblen",
        "mbrlen",
        "mbrtowc",
        "mbtowc",
        "memcmp",
        "mkdir",
        "mknod",
        "mkfifo",
        "mkstemp",
        "mkstemp64",
        "mktime",
        "modf",
        "mprotect",
        "munmap",
        "nanosleep",
        "nodelay",
        "open",
        "open64",
        "openlog",
        "openpty",
        "pathconf",
        "pclose",
        "perror",
        "pipe",
        "png_destroy_write_struct",
        "png_init_io",
        "png_set_bKGD",
        "png_set_invert_alpha",
        "png_set_invert_mono",
        "png_write_end",
        "png_write_info",
        "png_write_rows",
        "poll",
        "pread64",
        "printf",
        "pthread_attr_destroy",
        "pthread_attr_init",
        "pthread_attr_setscope",
        "pthread_attr_setstacksize",
        "pthread_create",
        "pthread_mutex_destroy",
        "pthread_mutex_init",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
        "pthread_mutexattr_destroy",
        "pthread_mutexattr_init",
        "pthread_mutexattr_settype",
        "ptsname",
        "putenv",
        "puts",
        "qsort",
        "re_compile_fastmap",
        "re_exec",
        "re_search",
        "read",
        "readlink",
        "recv",
        "recvfrom",
        "regcomp",
        "regerror",
        "remove",
        "rename",
        "rewind",
        "rewinddir",
        "rmdir",
        "rresvport",
        "scrollok",
        "select",
        "sem_destroy",
        "sem_init",
        "sem_post",
        "sem_trywait",
        "sem_wait",
        "send",
        "sendto",
        "setbuf",
        "setenv",
        "setgroups",
        "setitimer",
        "setrlimit",
        "setsockopt",
        "setvbuf",
        "sigaction",
        "sigaddset",
        "sigaltstack",
        "sigdelset",
        "sigemptyset",
        "sigfillset",
        "sigisemptyset",
        "sigismember",
        "siglongjmp",
        "sigprocmask",
        "sigsuspend",
        "snprintf",
        "socketpair",
        "sprintf",
        "sscanf",
        "stat",
        "stat64",
        "statfs",
        "statvfs",
        "statvfs64",
        "strcasecmp",
        "strcmp",
        "strcoll",
        "strcspn",
        "strfmon",
        "strftime",
        "strlen",
        "strncasecmp",
        "strncmp",
        "strspn",
        "symlink",
        "sysinfo",
        "syslog",
        "system",
        "tcgetattr",
        "tcsetattr",
        "tgetent",
        "tgetflag",
        "tgetnum",
        "time",
        "timegm",
        "times",
        "tputs",
        "truncate",
        "uname",
        "uncompress",
        "ungetc",
        "unlink",
        "unsetenv",
        "utime",
        "utimes",
        "vasprintf",
        "vfprintf",
        "vprintf",
        "vsnprintf",
        "vsprintf",
        "waddch",
        "waddnstr",
        "wait",
        "wait3",
        "wait4",
        "waitpid",
        "wattr_off",
        "wattr_on",
        "wborder",
        "wclrtobot",
        "wclrtoeol",
        "wcrtomb",
        "wctomb",
        "wctype",
        "werase",
        "wgetch",
        "wmove",
        "wrefresh",
        "write",
        "wtouchln",
        "\01_fopen",
        "\01fopen64",
        "\01readdir64",
        "\01tmpfile64",
        "BIO_new_socket",
        "FT_Get_Sfnt_Table",
        "FcFontList",
        "FcFontMatch",
        "FcFontRenderPrepare",
        "FcFontSetCreate",
        "FcFontSort",
        "FcInitLoadConfig",
        "FcObjectSetBuild",
        "FcObjectSetCreate",
        "FcPatternBuild",
        "FcPatternCreate",
        "FcPatternDuplicate",
        "SSL_CTX_new",
        "SSL_get_peer_certificate",
        "SSL_new",
        "SSLv23_client_method",
        "SyGetmem",
        "TLSv1_client_method",
        "Void_ExtendCore",
        "XAddExtension",
        "XAllocClassHint",
        "XAllocSizeHints",
        "XAllocStandardColormap",
        "XCreateFontSet",
        "XCreateImage",
        "XCreateGC",
        "XESetCloseDisplay",
        "XGetImage",
        "XGetModifierMapping",
        "XGetMotionEvents",
        "XGetVisualInfo",
        "XLoadQueryFont",
        "XListPixmapFormats",
        "XRenderFindFormat",
        "XRenderFindStandardFormat",
        "XRenderFindVisualFormat",
        "XOpenDisplay",
        "XSetErrorHandler",
        "XSetIOErrorHandler",
        "XShapeGetRectangles",
        "XShmCreateImage",
        "XSynchronize",
        "XcursorImageCreate",
        "XcursorLibraryLoadImages",
        "XcursorShapeLoadImages",
        "XineramaQueryScreens",
        "XkbGetMap",
        "XtAppCreateShell",
        "XtCreateApplicationContext",
        "XtOpenDisplay",
        "alloc",
        "alloc_check",
        "alloc_clear",
        "art_svp_from_vpath",
        "art_svp_vpath_stroke",
        "art_svp_writer_rewind_new",
        "art_svp_writer_rewind_reap",
        "art_vpath_dash",
        "cairo_create",
        "cairo_image_surface_create_for_data",
        "cairo_pattern_create_for_surface",
        "cairo_surface_create_similar",
        "calloc",
        "fopen",
        "fopen64",
        "fopencookie",
        "g_scanner_new",
        "gcry_sexp_nth_mpi",
        "gzdopen",
        "iconv_open",
        "jpeg_alloc_huff_table",
        "jpeg_alloc_quant_table",
        "lalloc",
        "lalloc_clear",
        "malloc",
        "nhalloc",
        "oballoc",
        "pango_cairo_font_map_create_context",
        "pcre_compile",
        "pcre_study",
        "permalloc",
        "png_create_info_struct",
        "png_create_write_struct",
        "popen",
        "pthread_getspecific",
        "readdir",
        "readdir64",
        "safe_calloc",
        "safe_malloc",
        "safecalloc",
        "safemalloc",
        "safexcalloc",
        "safexmalloc",
        "savealloc",
        "setmntent",
        "shmat",
        "__sysv_signal",
        "signal",
        "sigset",
        "tempnam",
        "tmpfile",
        "tmpfile64",
        "xalloc",
        "xcalloc",
        "xmalloc",
        "_Znwm",
        "_Znam",
        "_Znaj",
        "_Znwj",
        "__cxa_allocate_exception",
        "aligned_alloc",
        "memalign",
        "valloc",
        "SRE_LockCreate",
        "VOS_MemAlloc",
        "\01mmap64",
        "X509_NAME_oneline",
        "X509_verify_cert_error_string",
        "XBaseFontNameListOfFontSet",
        "XGetAtomName",
        "XGetDefault",
        "XGetKeyboardMapping",
        "XListDepths",
        "XListFonts",
        "XSetLocaleModifiers",
        "XcursorGetTheme",
        "__strdup",
        "crypt",
        "ctime",
        "dlerror",
        "dlopen",
        "gai_strerror",
        "gcry_cipher_algo_name",
        "gcry_md_algo_name",
        "gcry_md_read",
        "getenv",
        "getlogin",
        "getpass",
        "gnutls_strerror",
        "gpg_strerror",
        "gzerror",
        "inet_ntoa",
        "initscr",
        "llvm.stacksave",
        "mmap",
        "mmap64",
        "newwin",
        "nl_langinfo",
        "opendir",
        "sbrk",
        "strdup",
        "strerror",
        "strsignal",
        "textdomain",
        "tgetstr",
        "tigetstr",
        "tmpnam",
        "ttyname",
        "__ctype_b_loc",
        "__ctype_tolower_loc",
        "__ctype_toupper_loc",
        "XKeysymToString",
        "__errno_location",
        "__h_errno_location",
        "__res_state",
        "asctime",
        "bindtextdomain",
        "bind_textdomain_codeset",
        "ctermid",
        "dcgettext",
        "dgettext",
        "dngettext",
        "fdopen",
        "gcry_strerror",
        "gcry_strsource",
        "getgrgid",
        "getgrnam",
        "gethostbyaddr",
        "gethostbyname",
        "gethostbyname2",
        "getmntent",
        "getprotobyname",
        "getprotobynumber",
        "getpwent",
        "getpwnam",
        "getpwuid",
        "getservbyname",
        "getservbyport",
        "getspnam",
        "gettext",
        "gmtime",
        "gnu_get_libc_version",
        "gnutls_check_version",
        "localeconv",
        "localtime",
        "ngettext",
        "pango_cairo_font_map_get_default",
        "re_comp",
        "setlocale",
        "tgoto",
        "tparm",
        "zError",
        "getcwd",
        "mem_realloc",
        "realloc",
        "realloc_obj",
        "safe_realloc",
        "saferealloc",
        "safexrealloc",
        "strtok",
        "strtok_r",
        "xrealloc",
        "SSL_CTX_free",
        "SSL_free",
        "cfree",
        "free",
        "free_all_mem",
        "freeaddrinfo",
        "gcry_mpi_release",
        "gcry_sexp_release",
        "globfree",
        "nhfree",
        "obstack_free",
        "safe_cfree",
        "safe_free",
        "safefree",
        "safexfree",
        "sm_free",
        "vim_free",
        "xfree",
        "fclose",
        "_ZdaPv",
        "_ZdlPv",
        "__rawmemchr",
        "cairo_surface_reference",
        "fgets",
        "jpeg_std_error",
        "memchr",
        "mremap",
        "strchr",
        "strerror_r",
        "strpbrk",
        "strptime",
        "strrchr",
        "strstr",
        "tmpnam_r",
        "asctime_r",
        "bsearch",
        "getmntent_r",
        "gmtime_r",
        "gzgets",
        "localtime_r",
        "realpath",
        "\01freopen64",
        "_XGetAsyncReply",
        "freopen",
        "freopen64",
        "inet_ntop",
        "XGetSubImage",
        "memset",
        "llvm.memset",
        "llvm.memset.p0i8.i32",
        "llvm.memset.p0i8.i64",
        "llvm.memcpy",
        "llvm.memcpy.p0i8.p0i8.i32",
        "llvm.memcpy.p0i8.p0i8.i64",
        "llvm.memmove",
        "llvm.memmove.p0i8.p0i8.i32",
        "llvm.memmove.p0i8.p0i8.i64",
        "memccpy",
        "memcpy",
        "memmove",
        "dlsym",
        "bcopy",
        "iconv",
        "strtod",
        "strtof",
        "strtol",
        "strtold",
        "strtoll",
        "strtoul",
        "readdir_r",
        "__strcpy_chk",
        "__strcat_chk",
        "stpcpy",
        "strcat",
        "strcpy",
        "strncat",
        "strncpy",
        "getpwnam_r",
        "getpwuid_r",
        "db_create",
        "gcry_mpi_scan",
        "gcry_pk_decrypt",
        "gcry_sexp_build",
        "gnutls_pkcs12_bag_init",
        "gnutls_pkcs12_init",
        "gnutls_x509_crt_init",
        "gnutls_x509_privkey_init",
        "posix_memalign",
        "scandir",
        "XGetRGBColormaps",
        "XmbTextPropertyToTextList",
        "SRE_SplSpecCreate",
        "XQueryTree",
        "XGetWindowProperty",
        "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_",
        "_ZNSt8__detail15_List_node_base7_M_hookEPS0_",
        "_ZNSsC1EPKcRKSaIcE",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3_",
        "_ZNSsC1EPKcmRKSaIcE",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcmRKS3_",
        "_ZNSsaSEPKc",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc",
        "_ZNSsC1ERKSs",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1ERKS4_",
        "_ZNSsC1ERKSsmm",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1ERKS4_mm",
        "_ZNSsaSERKSs",
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSERKS4_",
        "_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKSbIS4_S5_T1_E",
        "_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKNSt7__cxx1112basic_stringIS4_S5_T1_EE",
        "__dynamic_cast",
        0,
};

static const ei_pair_t_map ei_pair_t_maps[] = {
    {"ExtAPI::EFT_NOOP", ExtAPI::EFT_NOOP},
    {"ExtAPI::EFT_ALLOC", ExtAPI::EFT_ALLOC},
    {"ExtAPI::EFT_NOSTRUCT_ALLOC", ExtAPI::EFT_NOSTRUCT_ALLOC},
    {"ExtAPI::EFT_STAT2", ExtAPI::EFT_STAT2},
    {"ExtAPI::EFT_STAT", ExtAPI::EFT_STAT},
    {"ExtAPI::EFT_REALLOC", ExtAPI::EFT_REALLOC},
    {"ExtAPI::EFT_FREE", ExtAPI::EFT_FREE},
    {"ExtAPI::EFT_L_A0", ExtAPI::EFT_L_A0},
    {"ExtAPI::EFT_L_A1", ExtAPI::EFT_L_A1},
    {"ExtAPI::EFT_L_A2", ExtAPI::EFT_L_A2},
    {"ExtAPI::EFT_L_A8", ExtAPI::EFT_L_A8},
    {"ExtAPI::EFT_L_A0__A0R_A1", ExtAPI::EFT_L_A0__A0R_A1},
    {"ExtAPI::EFT_L_A0__A0R_A1R", ExtAPI::EFT_L_A0__A0R_A1R},
    {"ExtAPI::EFT_L_A0__A2R_A0", ExtAPI::EFT_L_A0__A2R_A0},
    {"ExtAPI::EFT_L_A1__FunPtr", ExtAPI::EFT_L_A1__FunPtr},
    {"ExtAPI::EFT_A1R_A0R", ExtAPI::EFT_A1R_A0R},
    {"ExtAPI::EFT_A3R_A1R_NS", ExtAPI::EFT_A3R_A1R_NS},
    {"ExtAPI::EFT_A1R_A0", ExtAPI::EFT_A1R_A0},
    {"ExtAPI::EFT_A2R_A1", ExtAPI::EFT_A2R_A1},
    {"ExtAPI::EFT_L_A0__A1_A0", ExtAPI::EFT_L_A0__A1_A0},
    {"ExtAPI::EFT_A4R_A1", ExtAPI::EFT_A4R_A1},
    {"ExtAPI::EFT_A0R_NEW", ExtAPI::EFT_A0R_NEW},
    {"ExtAPI::EFT_A1R_NEW", ExtAPI::EFT_A1R_NEW},
    {"ExtAPI::EFT_A2R_NEW", ExtAPI::EFT_A2R_NEW},
    {"ExtAPI::EFT_A4R_NEW", ExtAPI::EFT_A4R_NEW},
    {"ExtAPI::EFT_A11R_NEW", ExtAPI::EFT_A11R_NEW},
    {"ExtAPI::EFT_STD_RB_TREE_INSERT_AND_REBALANCE",
     ExtAPI::EFT_STD_RB_TREE_INSERT_AND_REBALANCE},
    {"ExtAPI::EFT_STD_RB_TREE_INCREMENT", ExtAPI::EFT_STD_RB_TREE_INCREMENT},
    {"ExtAPI::EFT_STD_LIST_HOOK", ExtAPI::EFT_STD_LIST_HOOK},
    {"ExtAPI::CPP_EFT_A0R_A1", ExtAPI::CPP_EFT_A0R_A1},
    {"ExtAPI::CPP_EFT_A0R_A1R", ExtAPI::CPP_EFT_A0R_A1R},
    {"ExtAPI::CPP_EFT_A1R", ExtAPI::CPP_EFT_A1R},
    {"ExtAPI::EFT_CXA_BEGIN_CATCH", ExtAPI::EFT_CXA_BEGIN_CATCH},
    {"ExtAPI::CPP_EFT_DYNAMIC_CAST", ExtAPI::CPP_EFT_DYNAMIC_CAST},
    {"ExtAPI::EFT_OTHER", ExtAPI::EFT_OTHER}};

void ExtAPI::init()
{
  set<extf_t> t_seen;
  extf_t prev_t = EFT_NOOP;
  t_seen.insert(EFT_NOOP);
  ei_pair ei_pairs[736];
  std::string get_line, get_str, temp_str, ei_pair_n[736];
  char get_char;
  const char *n_char;
  ExtAPI::extf_t ei_pair_t[736];
  std::size_t pos_start, pos_end;
  bool getEIPairs = false;
  std::ifstream getEiPairs("lib/Util/summary.txt");
  int count = 0;

  if (getEiPairs.is_open())
  {
    while (std::getline(getEiPairs, get_line))
    {
      // Remove spaces
      for (char c : get_line)
      {
        if (c != ' ')
        {
          get_char = c;
          break;
        }
      }
      get_str = get_line.substr(get_line.find(get_char));
      if (get_str.find("ei_pair ei_pairs[]") == 0)
      {
        getEIPairs = true;
      }
      else if (get_str.find("};") == 0)
      {
        getEIPairs = false;
      }
      if (getEIPairs)
      {
        if (get_str.find("{") == 0)
        {
          pos_start = 1;
          pos_end = get_str.find(",") - 1;
          std::string n_str;
          for (char c : get_str.substr(pos_start, pos_end))
          {
            // Remove " "
            if (c != '"')
            {
              n_str += c;
            }
          }
          // Get const *char ei_pair_n
          if (n_str.find("\\01") == 0)
          {
            ei_pair_n[count] = '\01' + n_str.substr(3);
          }
          else if (n_str.find("0") == 0)
          {
            ei_pair_n[count] = "0";
          }
          else
          {
            ei_pair_n[count] = n_str;
          }
          // Get ExtAPI::extf_t ei_pair_t
          pos_start = get_str.find(",");
          std::string t_str;
          for (char c : get_str.substr(pos_start + 1))
          {
            if (c == '}')
            {
              break;
            }
            if (c != ' ')
            {
              t_str += c;
            }
          }
          for (ei_pair_t_map map : ei_pair_t_maps)
          {
            if (t_str.compare(map.t_string_ref) == 0)
            {
              ei_pair_t[count] = map.t_ref;
              break;
            }
          }
          count++;
        }
      }
    }
  }

  for (int i = 0; i < (sizeof(ei_pairs) / sizeof(*ei_pairs)); i++)
  {
    /*if (ei_pair_n[i] != "0")
    {
      n_char = ei_pair_n[i].c_str();
    }
    else
    {
      n_char = 0;
    }*/
    ei_pairs[i] = {ei_pair_n_maps[i].n_ref, ei_pair_t[i]};
  }

  /*const char *test1 = "test";
  std::string testStr = "test";
  const char *test2 = "test";

  if (strcmp(test1, testStr.c_str()) == 0)
  {
    std::cout << "true\n";
  }
  else
  {
    std::cout << "false\n";
  }*/

  for (const ei_pair *p = ei_pairs; p->n; ++p)
  {
    if (p->t != prev_t)
    {
      //This will detect if you move an entry to another block
      //  but forget to change the type.
      if (t_seen.count(p->t))
      {
        fputs(p->n, stderr);
        putc('\n', stderr);
        assert(!"ei_pairs not grouped by type");
      }
      t_seen.insert(p->t);
      prev_t = p->t;
    }
    if (info.count(p->n))
    {
      fputs(p->n, stderr);
      putc('\n', stderr);
      assert(!"duplicate name in ei_pairs");
    }
    info[p->n] = p->t;
  }
}

AC_INIT([arppy], [1.0], [github@foxfilter.foxpaws.net],[arppy],[https://github.com/foxbird/arppy])
AC_CONFIG_AUX_DIR(auto)
AC_CONFIG_SRCDIR([src/arppy.c])

AC_PROG_INSTALL
AC_PROG_CC
AC_PROG_MAKE_SET

AM_INIT_AUTOMAKE([-Wall -Werror foreign])

AC_CONFIG_HEADERS([include/autoconf.h])
AC_CONFIG_FILES([Makefile src/Makefile])

AC_CHECK_HEADERS([sys/socket.h],,[AC_MSG_ERROR([sys/socket.h is required])])
AC_CHECK_HEADERS([arpa/inet.h],,[AC_MSG_ERROR([arpa/inet.h is required])])
AC_CHECK_HEADERS([net/if.h],,[AC_MSG_ERROR([net/if.h is required])])
AC_CHECK_HEADERS([net/ethernet.h],,[AC_MSG_ERROR([net/ethernet.h is required])])
AC_CHECK_HEADERS([netinet/ip.h],,[AC_MSG_ERROR([netinet/ip.h is required])])
AC_CHECK_HEADERS([netinet/in.h],,[AC_MSG_ERROR([netinet/in.h is required])])
AC_CHECK_HEADERS([linux/if_packet.h],,[AC_MSG_ERROR([netinet/if_packet.h is required])])
AC_CHECK_HEADERS([linux/if_ether.h],,[AC_MSG_ERROR([netinet/if_ether.h is required])])
AC_CHECK_HEADERS([linux/filter.h],,[AC_MSG_ERROR([netinet/filter.h is required])])

AC_OUTPUT

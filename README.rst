===========
mod_visitor
===========

:Author: `Benedikt Böhm <bb@xnull.de>`_
:Version: 0.1
:Web: http://github.com/hollow/mod_visitor
:Git: ``git clone https://github.com/hollow/mod_visitor.git``
:Download: http://github.com/hollow/mod_visitor/downloads

mod_visitor is an apache module that provides a simple way to track site
visitors with cookies using an invisible gif image.

Description
===========

mod_visitor creates three tracking cookies, to identify unique visitors and
unique visits:

``__vtc``
  The `c` cookie has only session lifetime to identify each unique visit.

``__vtb``
  The `b` cookie has a short lifetime to still identify a session if the user
  has closed his browser, but reopens it before the session time expires.

``__vta``
  The `a` cookie has a long lifetime to identify each unique user.

mod_visitor provides a ``visitor-cookie`` handler for apache to serve the
smallest possible gif image along with the above mentioned cookies. This way
visitor tracking can be added easily to existing applications.

Installation
============

To compile and install this module, use ``apxs`` provided by the apache
webserver:
::

  apxs -i -a -c mod_visitor.c

Configuration
=============

In your apache configuration add one or more ``Location`` directives to serve
the tracking image:
::

  <Location "/__vt.gif">
      VisitorTracking On
      SetHandler visitor-cookie
      Allow from all

      # visitor cookies expire after about 2 years
      VisitorExpiry 63072000

      # session cookies expire after 30 minutes
      SessionExpiry 1800
  </Location>

You can then use the ``%{visitor-cookie}n`` format string in ``mod_log_config``
to log the visitor cookie to a logfile.

Directives
==========

VisitorTracking On|Off
  Enable/Disable visitor tracking

VisitorDomain *domain*
  Explicitly set cookie domain

VisitorExpiry *seconds*
  Set expiry time of the visitor cookie (``__vta``) in seconds

SessionExpiry *seconds*
  Set expiry time of the session cookie (``__vtb``) in seconds

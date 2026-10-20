#!/bin/zsh
# Lists the members of the local "admin" group (read-only).
set -u
print "Direct members (dscl):"
/usr/bin/dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/^GroupMembership: //' | tr ' ' '\n' | sed '/^$/d; s/^/  /'
print ""
print "Local user accounts that are admins (incl. nested groups):"
for u in $(/usr/bin/dscl . -list /Users UniqueID | awk '$2 >= 500 {print $1}'); do
  if /usr/sbin/dseditgroup -o checkmember -m "$u" admin >/dev/null 2>&1; then
    print "  $u"
  fi
done

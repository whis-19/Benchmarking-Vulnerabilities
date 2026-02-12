manager = Manager()
manager.create_dir("safeuser")  # Creates /tmp/safeuser
manager.create_dir("another_safe_user") # Creates /tmp/another_safe_user
manager.create_dir("unsafe; rm -rf /") # Will print "Invalid username..." and do nothing.


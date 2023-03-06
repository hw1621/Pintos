# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(priority-preservation) begin
(priority-preservation) main-thread starting...
(priority-preservation) main-thread creating medium-priority thread...
(priority-preservation) medium-priority thread starting...
(priority-preservation) medium-priority thread trying to acquire the lock...
(priority-preservation) main-thread continuing...
(priority-preservation) This thread should have priority 36.  Actual priority: 36.
(priority-preservation) main-thread creating high-priority thread...
(priority-preservation) high-priority thread starting...
(priority-preservation) high-priority thread trying to acquire the lock...
(priority-preservation) main-thread continuing...
(priority-preservation) This thread should have priority 41.  Actual priority: 41.
(priority-preservation) main-thread now releasing the lock...
(priority-preservation) high-priority thread got the lock.
(priority-preservation) high-priority thread about to drop to low priority...
(priority-preservation) This thread should still have effective priority 36.  Actual priority: 36.
(priority-preservation) medium-priority thread got the lock.
(priority-preservation) medium-priority thread done.
(priority-preservation) medium-priority thread must already have finished.
(priority-preservation) This should be the last line before finishing this test.
(priority-preservation) end
EOF
pass;

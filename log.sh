pod=`k get pods -n test | grep iam | awk '{print $1}'`

k logs pods/$pod -n test -f

pod=`k get pods -n test | grep web-iam-demo | grep Running | awk '{print $1}'`

k logs pods/$pod -n test -f

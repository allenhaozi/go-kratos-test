#! /bin/bash

if [ ! -n "$1" ];then
    echo "input version index!\n"
	exit
fi

set -x



index=$1



rm -rf ./iam-web

GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
		go build -a -ldflags "-s -w" -o iam-web main.go


docker build -t docker.4pd.io/openaios/iam/iam-web-demo:1.0.0-alpha.${index} .

docker push docker.4pd.io/openaios/iam/iam-web-demo:1.0.0-alpha.${index}

sh upgrade.sh

pod=`k get pods -n test | grep iam | awk '{print $1}'`

k delete pods/$pod -n test

htpasswd -c auth admin
kubectl create secret generic nginx-basic-auth \
  --from-file=auth \
  --namespace=monitoring

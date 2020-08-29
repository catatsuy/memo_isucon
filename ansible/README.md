# provisioning

```sh
ansible-playbook -i production site.yml -e ansible_python_interpreter=/usr/bin/python3

# CentOS
sudo yum install -y unzip
ansible-playbook -i production site.yml -e ansible_python_interpreter=/usr/bin/python3 --skip-tags ubuntu
```

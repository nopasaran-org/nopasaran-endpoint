ssh-keygen -f "/home/benhabbo/.ssh/known_hosts" -R "localhost"

ssh -R 80:localhost:5000 root@localhost

Password: your_password

nano /etc/ssh/sshd_config
## download required library
sudo apt-get install libpam0g-dev  
sudo apt-get install libssl-dev

## checkout pam_tacacs_plus
git clone https://github.com/jeroennijhof/pam_tacplus.git  
cd pam_tacplus  
git checkout -f v1.4.1  
cd pam_tacplus  
./auto.sh  
./configure  
make

=========================================  
need to check how to link
## checkout openssl
wget https://www.openssl.org/source/old/1.1.0/openssl-1.1.0i.tar.gz  
tar zxvf openssl-1.1.0i.tar.gz  
cd openssl-1.1.0i  
CROSS_COMPILE= perl Configure --prefix=/home/nms/code/sonic_tacacs/ssl linux-x86_64  
make

## checkout libpam
git clone https://github.com/linux-pam/linux-pam.git  
cd linux-pam  
./autogen.sh  
./configure  

==========================================

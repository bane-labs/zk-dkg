cd cmd
echo 'start run mpc'
bash test_mpc.sh
echo 'mpc finish'
cd ../
go test --run TestBatchEncryptionWithMPC -v --timeout=1440m

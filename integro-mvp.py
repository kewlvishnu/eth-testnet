#!/usr/bin/env python3

# pip install ecdsa
# pip install pysha3

from __future__ import print_function
import time
from kubernetes import client, config, watch
# from kubernetes.client.rest import ApiException
from pprint import pprint
from ecdsa import SigningKey, SECP256k1
import sha3
import json
import os
import sys



def checksum_encode(addr_str): # Takes a hex (string) address as input
    keccak = sha3.keccak_256()
    out = ''
    addr = addr_str.lower().replace('0x', '')
    keccak.update(addr.encode('ascii'))
    hash_addr = keccak.hexdigest()
    for i, c in enumerate(addr):
        if int(hash_addr[i], 16) >= 8:
            out += c.upper()
        else:
            out += c
    return '0x' + out

keccak = sha3.keccak_256()

priv = SigningKey.generate(curve=SECP256k1)
pub = priv.get_verifying_key().to_string()

keccak.update(pub)
address = keccak.hexdigest()[24:]

# def test(addrstr):
#     assert(addrstr == checksum_encode(addrstr))

# test('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed')
# test('0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359')
# test('0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB')
# test('0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb')
# test('0x7aA3a964CC5B0a76550F549FC30923e5c14EDA84')

# print("Private key:", priv.to_string().hex())
# print("Public key: ", pub.hex())
# print("Address:    ", checksum_encode(address))

# print(priv.to_string().hex())
# print(pub.hex())
# print(checksum_encode(address))

data = {}
data['wallet'] = []
data['wallet'].append({
    'Private key': priv.to_string().hex(),
    'Public key': pub.hex(),
    'Address': checksum_encode(address)
})

with open('data.txt', 'w') as outfile:
    json.dump(data, outfile)


with open('data.txt', 'r') as f:
    wallet_dict = json.load(f)

# #for wallet in wallet_dict:
# #    print(wallet_dict['wallet'][0]['Address'])

wallet_addr = wallet_dict['wallet'][0]['Address']
wallet_pvt_key = wallet_dict['wallet'][0]['Private key']

print (wallet_addr)
print (wallet_pvt_key)

eth_testnet_install_Cmd = "helm install --name hazy-turtlexyz1 stable/ethereum    --set geth.account.address={0}     --set geth.account.privateKey={1}    --set geth.account.secret=qwerty123".format(wallet_addr,wallet_pvt_key)
#print(eth_testnet_install_Cmd)

#http://thesmithfam.org/blog/2012/10/25/temporarily-suppress-console-output-in-python/


helm_install_Cmd = os.popen(eth_testnet_install_Cmd).read()

# suppress print message
#print(helm_install_Cmd)

# Wait for 3 minutes
print ("Waiting for test net to be created..............")
time.sleep(180)

### PY Library for KubeCTL
#https://github.com/kubernetes-client/python/blob/master/kubernetes/README.md

#below example: 
##https://github.com/kubernetes-client/python/blob/master/kubernetes/docs/CoreV1Api.md#list_namespaced_service

# Configure API key authorization: BearerToken
config.load_kube_config()
v1 = client.CoreV1Api()
api_instance = v1
namespace = 'default'
try: 
    api_response = api_instance.list_namespaced_service(namespace)
    #pprint(api_response)
except ApiException as e:
    print("Exception when calling CoreV1Api->list_namespaced_service: %s\n" % e)

# retrieve datatype of the service list response
# print(type(api_response))

# for parsing above data type:
# https://medium.com/programming-kubernetes/building-stuff-with-the-kubernetes-api-part-3-using-python-aea5ab16f627

for svc in api_response.items:
    if svc.spec.type == 'LoadBalancer':
        print("http://"+svc.status.load_balancer.ingress[0].hostname)



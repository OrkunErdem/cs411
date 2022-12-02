# -*- coding: utf-8 -*-
"""
Created on Sat Nov  6 20:02:00 2021

@author: Orkun
"""

import random
import requests

API_URL = 'http://10.36.52.109:6000'
#API_URL = 'http://cryptlygos.pythonanywhere.com'

my_id = 20701   

def getQ1():
  endpoint = '{}/{}/{}'.format(API_URL, "Q1", my_id )
  response = requests.get(endpoint) 	
  if response.ok:	
    res = response.json()
    print(res)
    n, t = res['n'], res['t']
    return n,t
  else: print(response.json())
#Q1a

  
#Q1b  
list = []
generator_list = []
for i in range(1,502):
  list.append(i)
  
for i in list:
  list1 = []
  for j in range(1,800):
    num = pow(i,j,751)
    if num not in list1:
      list1.append(num)
  if len(list1) == 750:
    generator_list.append(i)

print("Generators are:", generator_list)
#Q1c
n= 502
t=125
sub_possible_generators = []
sub_generators = []
for i in list:
  if pow(i, t, n) == 1:
    sub_possible_generators.append(i)

for j in sub_possible_generators:
  generated_items = []
  for k in range(1,201):
    if pow(j, k, n) not in generated_items:
      generated_items.append(pow(j, k, n))

  if len(generated_items) == 125:
    generated_items.sort()
    #print(j, generated_items)
    sub_generators.append(j)

print("Subsequence generators are:", sub_generators)



def checkQ1a(order):   #check your answer for Question 1 part a
  endpoint = '{}/{}/{}/{}'.format(API_URL, "checkQ1a", my_id, order)
  response = requests.put(endpoint) 	
  print(response.json())

def checkQ1b(g):  #check your answer for Question 1 part b
  endpoint = '{}/{}/{}/{}'.format(API_URL, "checkQ1b", my_id, g )	#gH is generator of your subgroup
  response = requests.put(endpoint) 	#check result
  print(response.json())

def checkQ1c(gH):  #check your answer for Question 1 part c
  endpoint = '{}/{}/{}/{}'.format(API_URL, "checkQ1c", my_id, gH )	#gH is generator of your subgroup
  response = requests.put(endpoint) 	#check result
  print(response.json())

g=generator_list
gh=sub_generators

checkQ1b(g)
checkQ1c(gh)

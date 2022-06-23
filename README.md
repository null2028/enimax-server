# How to deploy

Change the environment variable in the .env file to store the secret
Make sure the redis server is already running. Then run:
```
npm install
```

and then, finally:
```
node server.js
```

# How to deploy on Glitch
    
Install redis on your Glitch project: [http://redis-notes.glitch.me/](http://redis-notes.glitch.me/). 
Instead of `package.json`, use `package-glitch.json` and Glitch should take care of the rest.

Or you can just remix this project: [https://glitch.com/edit/#!/glistening-square-fenugreek](https://glitch.com/edit/#!/glistening-square-fenugreek)
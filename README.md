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

# How to remix on Glitch

1. Go to [https://glitch.com/edit/#!/glistening-square-fenugreek](https://glitch.com/edit/#!/glistening-square-fenugreek).
2. Click on `Remix`.
3. It will take a bit for it to make a new project. After it's done, go to your `.env` file and enter the secret; it can be anything, but make sure it's long enough and has no patterns.
4. Then click on the `Preview` button on the bottom and then `Preview in a new window`.
5. Copy the URL from the window that just opened up.
6. Then you can simply follow this: [https://github.com/enimax-anime/enimax#synchronizing-across-devices](https://github.com/enimax-anime/enimax#synchronizing-across-devices)


# How to deploy on Glitch
    
Install redis on your Glitch project: [http://redis-notes.glitch.me/](http://redis-notes.glitch.me/). 
Instead of `package.json`, use `package-glitch.json` and Glitch should take care of the rest.

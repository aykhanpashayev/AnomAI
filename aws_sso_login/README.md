## How to login to AWS SSO via CLI?

### Step 1

```
First Login to your console as you usually do with the link in groupchat. Login with your username, password and authenticate.
```
### Step 2

```
Once you logged in you will see AWS Access Portal and AnomAI there with account number and email. Next to the AnomAI there's extension button click there and you should see AnomAIPowerUser | Access keys.
```

### Step 3

```
Click on Access keys you will see multiple options top login choose option one, simply copy and paste it to terminal.
```

### Lastly, how to check if you are logged in?

Run in terminal:
```
aws sts get-caller-identity
```

This should return your userId, Account number and Arn

You all set!
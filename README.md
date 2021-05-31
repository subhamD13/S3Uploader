# REST APIs for login Authentication & s3 data upload using Flask
## Procedure to upload files securely:
1. Upload File: [GET] /file-upload/<file_name>
    a) using this api Front-End will get time limited Presigned URL. 
    b) Using that URL and [PUT] method we can upload the exact file.

2. List all files: [GET] /file
3. Delete file: [DELETE] /file
    body: {
        'file_path': 'test/abc.pdf'
    }
4. Create folder: [POST] /folder
    body: {
        'folder': 'test'
    }
5. Delete folder: [DELETE] /folder
    body: {
        'folder': 'test'
    }
6. LogIn: [GET] /login
    Authorize using Username and Password.
7. Get all User details: [GET] /user
    Only admin can get these details.
8. Get specific User details: [GET] /user/<public_id>
    Only admin can get these details.
9. Promote specific User to Admin: [PUT] /user/<public_id>
    Only admin can do the task.
10. Delete specific User: [GET] /user/<public_id>
    Only admin can do the task.
11. SignIn: [POST] /user
    body: {
        "name": "Adi", 
        "password": "1234"
    }
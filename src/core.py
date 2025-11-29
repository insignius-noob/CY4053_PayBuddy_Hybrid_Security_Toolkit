import os

def read_file_content(filepath):
    #cheking if the file exists
    if not os.path.exists(filepath):
        return None 
    
    #opening the file and reading its contents
    with open (filepath, "r", encoding="utf-8") as file:
        content = file.read().strip()

        #if the file is incase empty
        if not content:
            return None
        
        #if the file is not empty, return the content inside of it
        return content
from core.libs import Http
from core.libs.all.show_msg import alert_bug
from .upload import Upload
from logging import getLogger

log = getLogger('scant3r')


def main(opts: dict, http: Http):
    result_file_upload = Upload(opts, http).start()
    list_file_upload = []

    if type(result_file_upload) is dict and 'message' in result_file_upload:
        if 'vulns' in result_file_upload: 
            for file_upload in result_file_upload['vulns']:
                if "response" in file_upload.keys() and 'message' in file_upload.keys():
                    upload = alert_bug(
                        "FILE UPLOAD",
                        file_upload['response'],
                        json=opts['json'],
                    )
                    list_file_upload.append(upload)

            if opts['json']:
                print(list_file_upload)
        else:
            log.debug(result_file_upload['message'])
    else:
        log.debug("Error during the execution of the file upload module")

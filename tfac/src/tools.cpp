#include "inc/include.h"
#include <Softpub.h>
#pragma comment(lib, "wintrust")

namespace tools
{
    bool memcpy_eh(void *dst, const void *src, size_t len)
	{
        auto psrc = (void*)src;
		__try
		{
            for (size_t i = 0; i < len; i++)
            {
                reinterpret_cast<uint8_t*>(dst)[i] =
                    reinterpret_cast<uint8_t*>(psrc)[i];
            }
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}

		return true;
	}
    
    cert_info_t get_cert_info(const char *path)
    {
        cert_info_t rs;
        memset(&rs, 0, sizeof rs);

        DWORD encoding, content_type, format_type, signer_info_len;
        HCERTSTORE store_handle = 0;
        HCRYPTMSG cmsg = 0;
        wchar_t wpath[MAX_PATH];
        memset(wpath, 0, sizeof wpath);
        mb2ws(path, wpath, sizeof wpath);

        // Try to query certificate using CryptQueryObject
        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath,
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                             CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                             &encoding, &content_type, &format_type,
                             &store_handle, &cmsg, 0))
        {
            if (!CryptMsgGetParam(cmsg,
                                  CMSG_SIGNER_INFO_PARAM,
                                  0,
                                  NULL,
                                  &signer_info_len))
            {
                rs.lookup_status = cert_lookup_states::FAILED_QUERY_SIGNER_INFO;
                CryptMsgClose(cmsg);
                CertCloseStore(store_handle, 0);
                return rs;
            }

            auto signer_info = (PCMSG_SIGNER_INFO)malloc(signer_info_len);
            if (signer_info)
            {
                memset(signer_info, 0, signer_info_len);

                if (CryptMsgGetParam(cmsg,
                                     CMSG_SIGNER_INFO_PARAM,
                                     0,
                                     signer_info,
                                     &signer_info_len))
                {
                    char serial_num[256];
                    memset(serial_num, 0, sizeof serial_num);
                    cert_read_serial_num(&signer_info->SerialNumber, serial_num, sizeof serial_num);

                    rs.serial_no = reverse_sn(std::string(serial_num));

                    CERT_INFO cinf;
                    cinf.Issuer = signer_info->Issuer;
                    cinf.SerialNumber = signer_info->SerialNumber;

                    auto cctx = CertFindCertificateInStore(store_handle,
                                                           X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                                           CERT_FIND_SUBJECT_CERT, &cinf, NULL);

                    if (cctx)
                    {
                        char issuer[64];
                        memset(issuer, 0, sizeof issuer);

                        CertGetNameStringA(cctx,
                                           CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                           CERT_NAME_ISSUER_FLAG, NULL,
                                           issuer, sizeof issuer);
                        rs.issuer = std::string(issuer);

                        auto name_count = CertGetNameStringA(cctx,
                                                             CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                                             0, NULL, NULL, 0);

                        if (name_count > 0)
                        {
                            auto name_len = (name_count * sizeof(wchar_t));
                            auto name = malloc(name_len + sizeof(wchar_t));

                            if (name)
                            {
                                memset(name, 0, name_len + sizeof(wchar_t));

                                if (CertGetNameStringA(cctx,
                                                       CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                                       0, NULL, (LPSTR)name, name_count) == name_count)
                                {
                                    rs.name = std::string((char *)name);
                                }

                                free(name);
                            }
                        }
                    }

                    free(signer_info);

                    rs.lookup_status = cert_lookup_states::OK;

                    CryptMsgClose(cmsg);
                    CertCloseStore(store_handle, 0);

                    return rs;
                }

                free(signer_info);
            }

            rs.lookup_status = cert_lookup_states::FAILED_ALLOC_SIGNER_INFO;

            CryptMsgClose(cmsg);
            CertCloseStore(store_handle, 0);

            return rs;
        }

        /* in case no embedded cert is found, we will not bother with the hash catalogue bullshit. */
        if (wcsstr(wpath, L"C:\\Windows\\"))
        {
            rs.lookup_status = cert_lookup_states::OK;
            rs.issuer = "WVT";
            rs.name = "WVT";
            rs.serial_no = "WVT";
            return rs;
        }

        rs.lookup_status = cert_lookup_states::FAILED_QUERY_FILE;

        return rs;
    }
}

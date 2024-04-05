#include "pcap_wrap.h"
#include <iphlpapi.h>

/*
 * 1. Download Npcap installer from https://npcap.com/dist/npcap-1.79.exe
 * 2. Run the exe to install the dlls to C:\Windows\System32\Npcap
 * 3. Add C:\Windows\System32\Npcap to the "Path" System environment variable
 * 4. Download the npcap SDK from https://npcap.com/#download
 * 5. Extract the npcap-sdk-1.13.zip to the preferred location
 * 6. Edit the path of wpcap.lib below
 * 7. Edit the AdditionalIncludeDirectories in the  mod_aes67.vcproj with Include directory path inside
 *    the ncpap-sdk directory
*/
#pragma comment(lib, "C:\\Users\\asymptotic\\Downloads\\npcap-sdk-1.13\\Lib\\x64\\wpcap.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

//FIXME: change camelcase to snake case
void get_adapter_desc(char *iface_name, char *description)
{
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	ULONG outBufLen = 0;
	ULONG family = AF_INET;
	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
	outBufLen = 15000;
	ULONG Iterations = 0;
	DWORD dwRetVal = 0;
	// Set the flags to pass to GetAdaptersAddresses
	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER |
				  GAA_FLAG_INCLUDE_TUNNEL_BINDINGORDER;
	if (iface_name == NULL || description == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "\n iface or desc is NULL\n");
		return;
	}

	do {
		pAddresses = (IP_ADAPTER_ADDRESSES *)MALLOC(outBufLen);
		if (pAddresses == NULL) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,
							  "Memory allocation failed for IP_ADAPTER_ADDRESSES struct\n");
			exit(1);
		}

		dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

		if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
			FREE(pAddresses);
			pAddresses = NULL;
		} else {
			break;
		}

		Iterations++;

	} while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

	if (dwRetVal == NO_ERROR) {
		pCurrAddresses = pAddresses;
		while (pCurrAddresses) {
			// A multibyte(wide) character can be one or two bytes,
			// we should allot two bytes for each character.
			// Record the length of the original string and add 1 to it to
			// account for the terminating null character.
			size_t fname_len = 2 * (wcslen(pCurrAddresses->FriendlyName) + 1);
			char fname[1000]; //FIXME get a MACRO
			size_t converted_chars = 0;
			wcstombs_s(&converted_chars, fname, fname_len, pCurrAddresses->FriendlyName, _TRUNCATE);

			if (0 == strcmp(iface_name, fname)) {
				char desc[1000]; // FIXME get a MACRO
				size_t desc_len = 2 * (wcslen(pCurrAddresses->Description) + 1);
				wcstombs_s(&converted_chars, desc, desc_len, pCurrAddresses->Description, _TRUNCATE);
				strncpy(description, desc,
						desc_len);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "sending desc: %s\n", desc);
				break;
			}
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%wS: %wS not matching with %s\n", pCurrAddresses->FriendlyName,
							  (char *)pCurrAddresses->Description, iface_name);
			pCurrAddresses = pCurrAddresses->Next;
		}
		FREE(pAddresses);
		pAddresses = NULL;
	}
}

pcap_t *
open_pcap_fp (char *iface_name)
{
    pcap_t *fp = NULL;
	pcap_if_t *alldevs, *d;

    char errbuf[PCAP_ERRBUF_SIZE];
	char iface_desc[1000]; // FIXME get a macro

	    /* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		return NULL;
	}

	get_adapter_desc(iface_name, iface_desc);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "got interface description: %s\n", iface_desc);

	/* Print the list */
	for (d = alldevs; d; d = d->next) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "description for %s, %s\n", d->name, d->description);
		if (strstr(d->description, iface_desc)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Going to use source: %s\n", d->name);
			break;
		}
	}

	if (d == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, " No description matched\n");
		return NULL;
	}

    /* Open the device */
    if ( (fp = pcap_open(d->name,
                        100 /*snaplen*/,
                        PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                        100 /*read timeout*/,
                        NULL /* remote authentication */,
                        errbuf)
                        ) == NULL)
    {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR,"\nError opening adapter: %s\n", errbuf);
    }

	struct bpf_program fcode;
	bpf_u_int32 netmask = 0xffffff;
	char filter[100] = "dst host 224.0.1.129"; //check for only _DFLT domain (i.e. 0)
	int res = PCAP_ERROR;
	// compile the filter
	if ((res = pcap_compile(fp, &fcode, filter, 1, netmask)) < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "\nError compiling filter: %s\n",
						  pcap_statustostr(res));
		pcap_close(fp);
		return NULL;
	}

	// set the filter
	if ((res = pcap_setfilter(fp, &fcode)) < 0) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "\nError setting the filter: %s\n",
						  pcap_statustostr(res));
		pcap_close(fp);
		return NULL;
	}

    return fp;

}

void close_pcap_fp(pcap_t *fp) { pcap_close(fp); }
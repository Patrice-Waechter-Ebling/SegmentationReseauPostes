//SegmentationReseauPostes.cpp

#include <windows.h>
#include <commctrl.h>
#include <stdio.h>

#pragma comment(lib, "comctl32.lib")

// IDs
#define IDC_IP_EDIT      1001
#define IDC_CIDR_EDIT    1002
#define IDC_NB_EDIT      1003
#define IDC_HOSTS_EDIT   1004
#define IDC_CALC_BTN     1005
#define IDC_COPYALL_BTN  1006
#define IDC_MASK_EDIT    1007
#define IDC_LISTVIEW     1008

// ----------------------
// Conversion IP / Masque
// ----------------------
unsigned long ip_to_ulong(const char* ip)
{
    unsigned int a,b,c,d;
    if(sscanf(ip, "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return 0;
    return (a<<24)|(b<<16)|(c<<8)|d;
}

void ulong_to_ip(unsigned long ip, char* out)
{
    sprintf(out, "%u.%u.%u.%u",
        (ip>>24)&255,
        (ip>>16)&255,
        (ip>>8)&255,
        ip&255
    );
}

unsigned long cidr_to_mask(int cidr)
{
    if(cidr <= 0) return 0;
    return 0xFFFFFFFF << (32 - cidr);
}

void MaskFromCIDR(int cidr, char* out)
{
    unsigned long mask = cidr_to_mask(cidr);
    sprintf(out, "%u.%u.%u.%u",
        (mask>>24)&255,
        (mask>>16)&255,
        (mask>>8)&255,
        mask&255
    );
}

// ----------------------
// Validation
// ----------------------
BOOL IsValidIP(const char* ip)
{
    int a,b,c,d;
    if(sscanf(ip, "%d.%d.%d.%d", &a,&b,&c,&d) != 4)
        return FALSE;

    if(a<0||a>255||b<0||b>255||c<0||c>255||d<0||d>255)
        return FALSE;

    char tmp[32];
    sprintf(tmp, "%d.%d.%d.%d", a,b,c,d);
    return strcmp(tmp, ip) == 0;
}

BOOL IsValidCIDR(const char* s)
{
    int c = atoi(s);
    return (c >= 0 && c <= 32);
}

// ----------------------
// Classe IP ? CIDR base
// ----------------------
int DetectCIDRFromIP(const char* ip)
{
    unsigned int a,b,c,d;
    if(sscanf(ip, "%u.%u.%u.%u", &a,&b,&c,&d) != 4)
        return -1;

    if(a <= 127) return 8;     // A
    if(a <= 191) return 16;    // B
    return 24;                 // C
}

// ----------------------
// Clipboard
// ----------------------
void CopyToClipboard(HWND hwnd, const char* text)
{
    if(!OpenClipboard(hwnd)) return;
    EmptyClipboard();

    size_t len = strlen(text) + 1;
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
    memcpy(GlobalLock(hMem), text, len);
    GlobalUnlock(hMem);

    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();
}

// ----------------------
// ListView
// ----------------------
HWND CreateListView(HWND hwndParent)
{
    HWND hLV = CreateWindowEx(
        WS_EX_CLIENTEDGE, WC_LISTVIEW, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        10, 140, 780, 360,
        hwndParent, (HMENU)IDC_LISTVIEW, GetModuleHandle(NULL), NULL);

    ListView_SetExtendedListViewStyle(hLV,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    LVCOLUMN col;
    col.mask = LVCF_TEXT | LVCF_WIDTH;

    col.pszText = "Réseau";     col.cx = 160; ListView_InsertColumn(hLV, 0, &col);
    col.pszText = "Broadcast";  col.cx = 160; ListView_InsertColumn(hLV, 1, &col);
    col.pszText = "1er hôte";   col.cx = 160; ListView_InsertColumn(hLV, 2, &col);
    col.pszText = "Dernier";    col.cx = 160; ListView_InsertColumn(hLV, 3, &col);

    return hLV;
}

void CopyAllListView(HWND hwndLV, HWND hwnd)
{
    int count = ListView_GetItemCount(hwndLV);
    if(count <= 0) return;

    char buffer[16384] = {0};
    char tmp[256];

    for(int i=0; i<count; i++)
    {
        ListView_GetItemText(hwndLV, i, 0, tmp, 255);
        strcat(buffer, tmp); strcat(buffer, "\t");

        ListView_GetItemText(hwndLV, i, 1, tmp, 255);
        strcat(buffer, tmp); strcat(buffer, "\t");

        ListView_GetItemText(hwndLV, i, 2, tmp, 255);
        strcat(buffer, tmp); strcat(buffer, "\t");

        ListView_GetItemText(hwndLV, i, 3, tmp, 255);
        strcat(buffer, tmp); strcat(buffer, "\r\n");
    }

    CopyToClipboard(hwnd, buffer);
}

// ----------------------
// Calcul CIDR pour sous-réseaux / hôtes
// ----------------------
int CIDRForSubnets(int base_cidr, int nb_subnets)
{
    int k = 0;
    while((1 << k) < nb_subnets) k++;
    return base_cidr + k;
}

int CIDRForHosts(int hosts)
{
    for(int cidr = 32; cidr >= 0; cidr--)
    {
        unsigned long block = 1UL << (32 - cidr);
        unsigned long usable = (cidr <= 30) ? block - 2 : 0;

        if(usable >= (unsigned long)hosts)
            return cidr;
    }
    return -1;
}

// ----------------------
// Calcul principal
// ----------------------
void DoCalculation(HWND hwnd)
{
    char ip_str[32], cidr_str[8], nb_str[16], hosts_str[16];
    GetDlgItemText(hwnd, IDC_IP_EDIT, ip_str, 31);
    GetDlgItemText(hwnd, IDC_CIDR_EDIT, cidr_str, 7);
    GetDlgItemText(hwnd, IDC_NB_EDIT, nb_str, 15);
    GetDlgItemText(hwnd, IDC_HOSTS_EDIT, hosts_str, 15);

    if(!IsValidIP(ip_str) || !IsValidCIDR(cidr_str))
        return;

    int cidr = atoi(cidr_str);
    int nb   = atoi(nb_str);
    int hosts = atoi(hosts_str);

    if(nb <= 0) nb = 1;
    if(hosts < 0) hosts = 0;

    unsigned long ip   = ip_to_ulong(ip_str);
    unsigned long mask = cidr_to_mask(cidr);
    unsigned long base_net = ip & mask;

    // CIDR selon sous-réseaux
    int cidr_subnets = CIDRForSubnets(cidr, nb);

    // CIDR selon hôtes
    int cidr_hosts = (hosts > 0) ? CIDRForHosts(hosts) : cidr;

    // CIDR final
    int final_cidr = (cidr_hosts > cidr_subnets) ? cidr_hosts : cidr_subnets;
    if(final_cidr > 32) final_cidr = 32;

    unsigned long block = 1UL << (32 - final_cidr);

    // masque décimal affiché
    char mask_dec[32];
    MaskFromCIDR(final_cidr, mask_dec);
    SetDlgItemText(hwnd, IDC_MASK_EDIT, mask_dec);

    HWND hLV = GetDlgItem(hwnd, IDC_LISTVIEW);
    ListView_DeleteAllItems(hLV);

    for(int i = 0; i < nb; i++)
    {
        unsigned long net = base_net + (i * block);
        unsigned long bc  = net + block - 1;

        char sNet[32], sBc[32], sH1[32], sH2[32];
        ulong_to_ip(net, sNet);
        ulong_to_ip(bc, sBc);

        if(final_cidr <= 30)
        {
            ulong_to_ip(net+1, sH1);
            ulong_to_ip(bc-1, sH2);
        }
        else
        {
            strcpy(sH1, "-");
            strcpy(sH2, "-");
        }

        LVITEM item;
        item.mask = LVIF_TEXT;
        item.iItem = i;
        item.iSubItem = 0;
        item.pszText = sNet;
        ListView_InsertItem(hLV, &item);

        ListView_SetItemText(hLV, i, 1, sBc);
        ListView_SetItemText(hLV, i, 2, sH1);
        ListView_SetItemText(hLV, i, 3, sH2);
    }
}

// ----------------------
// WndProc
// ----------------------
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch(msg)
    {
        case WM_CREATE:
        {
            CreateWindow("STATIC", "IP :", WS_CHILD|WS_VISIBLE,
                10,10,40,20, hwnd, 0, 0, 0);
            CreateWindow("EDIT", "192.168.1.0",
                WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                60,10,120,20, hwnd, (HMENU)IDC_IP_EDIT, 0, 0);

            CreateWindow("STATIC", "CIDR :", WS_CHILD|WS_VISIBLE,
                200,10,40,20, hwnd, 0, 0, 0);
            CreateWindow("EDIT", "24",
                WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                250,10,40,20, hwnd, (HMENU)IDC_CIDR_EDIT, 0, 0);

            CreateWindow("STATIC", "Sous-réseaux :", WS_CHILD|WS_VISIBLE,
                310,10,90,20, hwnd, 0, 0, 0);
            CreateWindow("EDIT", "4",
                WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                410,10,40,20, hwnd, (HMENU)IDC_NB_EDIT, 0, 0);

            CreateWindow("STATIC", "Hôtes max :", WS_CHILD|WS_VISIBLE,
                470,10,70,20, hwnd, 0, 0, 0);
            CreateWindow("EDIT", "",
                WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                540,10,60,20, hwnd, (HMENU)IDC_HOSTS_EDIT, 0, 0);

            CreateWindow("BUTTON", "Calculer",
                WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                610,10,80,25, hwnd, (HMENU)IDC_CALC_BTN, 0, 0);

            CreateWindow("BUTTON", "Copier tout",
                WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                700,10,90,25, hwnd, (HMENU)IDC_COPYALL_BTN, 0, 0);

            CreateWindow("STATIC", "Masque :", WS_CHILD|WS_VISIBLE,
                10,40,60,20, hwnd, 0, 0, 0);
            CreateWindow("EDIT", "",
                WS_CHILD|WS_VISIBLE|WS_BORDER|ES_READONLY,
                80,40,120,20, hwnd, (HMENU)IDC_MASK_EDIT, 0, 0);

            CreateListView(hwnd);
        }
        break;

        case WM_COMMAND:
        {
            WORD id = LOWORD(wParam);
            WORD code = HIWORD(wParam);

            if(id == IDC_CALC_BTN && code == BN_CLICKED)
                DoCalculation(hwnd);

            if(id == IDC_COPYALL_BTN && code == BN_CLICKED)
            {
                HWND hLV = GetDlgItem(hwnd, IDC_LISTVIEW);
                CopyAllListView(hLV, hwnd);
            }

            if(id == IDC_IP_EDIT && code == EN_CHANGE)
            {
                char ip[32];
                GetDlgItemText(hwnd, IDC_IP_EDIT, ip, 31);

                int base = DetectCIDRFromIP(ip);
                if(base > 0)
                {
                    char buf[8];
                    sprintf(buf, "%d", base);
                    SetDlgItemText(hwnd, IDC_CIDR_EDIT, buf);
                }
            }

            if(id == IDC_CIDR_EDIT && code == EN_CHANGE)
            {
                char buf[8];
                GetDlgItemText(hwnd, IDC_CIDR_EDIT, buf, 7);

                if(IsValidCIDR(buf))
                {
                    int cidr = atoi(buf);
                    char mask[32];
                    MaskFromCIDR(cidr, mask);
                    SetDlgItemText(hwnd, IDC_MASK_EDIT, mask);
                }
            }

            if(id == IDC_NB_EDIT && code == EN_CHANGE)
            {
                char ip[32], nb_str[16];
                GetDlgItemText(hwnd, IDC_IP_EDIT, ip, 31);
                GetDlgItemText(hwnd, IDC_NB_EDIT, nb_str, 15);

                int nb = atoi(nb_str);
                int base = DetectCIDRFromIP(ip);

                if(nb > 0 && base > 0)
                {
                    int cidr = CIDRForSubnets(base, nb);
                    if(cidr <= 32)
                    {
                        char buf[8];
                        sprintf(buf, "%d", cidr);
                        SetDlgItemText(hwnd, IDC_CIDR_EDIT, buf);
                    }
                }
            }

            if(id == IDC_HOSTS_EDIT && code == EN_CHANGE)
            {
                char h_str[16];
                GetDlgItemText(hwnd, IDC_HOSTS_EDIT, h_str, 15);

                int h = atoi(h_str);
                if(h > 0)
                {
                    int cidr = CIDRForHosts(h);
                    if(cidr >= 0)
                    {
                        char buf[8];
                        sprintf(buf, "%d", cidr);
                        SetDlgItemText(hwnd, IDC_CIDR_EDIT, buf);
                    }
                }
            }
        }
        break;

        case WM_NOTIFY:
        {
            LPNMHDR hdr = (LPNMHDR)lParam;
            if(hdr->idFrom == IDC_LISTVIEW && hdr->code == NM_DBLCLK)
            {
                HWND hLV = hdr->hwndFrom;
                int sel = ListView_GetNextItem(hLV, -1, LVNI_SELECTED);
                if(sel >= 0)
                {
                    char buf[512], tmp[128];

                    ListView_GetItemText(hLV, sel, 0, tmp, 127);
                    sprintf(buf, "Réseau: %s\r\n", tmp);

                    ListView_GetItemText(hLV, sel, 1, tmp, 127);
                    sprintf(buf + strlen(buf), "Broadcast: %s\r\n", tmp);

                    ListView_GetItemText(hLV, sel, 2, tmp, 127);
                    sprintf(buf + strlen(buf), "1er hôte: %s\r\n", tmp);

                    ListView_GetItemText(hLV, sel, 3, tmp, 127);
                    sprintf(buf + strlen(buf), "Dernier: %s\r\n", tmp);

                    CopyToClipboard(hwnd, buf);
                }
            }
        }
        break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ----------------------
// WinMain
// ----------------------
int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow)
{
    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASS wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
	wc.hIcon=LoadIcon(wc.hInstance,(LPCTSTR)101);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
    wc.lpszClassName = "SegmentationReseauPostes";
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);

    RegisterClass(&wc);

    HWND hwnd = CreateWindow(
        wc.lpszClassName,
        "Segmentation Réseau - Favoriser les machines",
        WS_OVERLAPPED| WS_CAPTION | WS_SYSMENU ,
        CW_USEDEFAULT, CW_USEDEFAULT,
        820, 550,
        NULL, NULL, hInst, NULL);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while(GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
}

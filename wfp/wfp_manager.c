#include "wfp_manager.h"
#include "../src/logger.h"
#include <initguid.h>

// Sublayer GUID {A4324F9A-407C-4C98-A8A2-E404E26A9A01}
DEFINE_GUID(GUID_IDENTITYNET_SUBLAYER,
    0xa4324f9a, 0x407c, 0x4c98, 0xa8, 0xa2, 0xe4, 0x4, 0xe2, 0x6a, 0x9a, 0x1);

// FWPM_LAYER_ALE_AUTH_CONNECT_V4 {C38624F0-5A18-4649-90B8-B0B51D3D8650}
DEFINE_GUID(GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    0xc38624f0, 0x5a18, 0x4649, 0x90, 0xb8, 0xb0, 0xb5, 0x1d, 0x3d, 0x86, 0x50);

// FWPM_CONDITION_IP_REMOTE_PORT {C35A0928-D0F0-4B78-8085-D2D0B0D876BF}
DEFINE_GUID(GUID_FWPM_CONDITION_IP_REMOTE_PORT,
    0xc35a0928, 0xd0f0, 0x4b78, 0x80, 0x85, 0xd2, 0xd0, 0xb0, 0xd8, 0x76, 0xbf);

// FWPM_CONDITION_IP_REMOTE_ADDRESS {1A82E98D-6E76-4C2E-A9B0-A182C1D13550}
DEFINE_GUID(GUID_FWPM_CONDITION_IP_REMOTE_ADDRESS,
    0x1a82e98d, 0x6e76, 0x4c2e, 0xa9, 0xb0, 0xa1, 0x82, 0xc1, 0xd1, 0x35, 0x50);

// WFP API Function Pointers (from fwpuclnt.dll)
typedef DWORD (WINAPI *pfn_FwpmEngineOpen0)(LPCWSTR, UINT32, SEC_WINNT_AUTH_IDENTITY_W*, const FWPM_SESSION0*, HANDLE*);
typedef DWORD (WINAPI *pfn_FwpmEngineClose0)(HANDLE);
typedef DWORD (WINAPI *pfn_FwpmSubLayerAdd0)(HANDLE, const FWPM_SUBLAYER0*, PSECURITY_DESCRIPTOR);
typedef DWORD (WINAPI *pfn_FwpmSubLayerDeleteByKey0)(HANDLE, const GUID*);
typedef DWORD (WINAPI *pfn_FwpmFilterAdd0)(HANDLE, const FWPM_FILTER0*, PSECURITY_DESCRIPTOR, UINT64*);

static HMODULE g_hWfpDll = NULL;
static pfn_FwpmEngineOpen0 pFwpmEngineOpen0 = NULL;
static pfn_FwpmEngineClose0 pFwpmEngineClose0 = NULL;
static pfn_FwpmSubLayerAdd0 pFwpmSubLayerAdd0 = NULL;
static pfn_FwpmSubLayerDeleteByKey0 pFwpmSubLayerDeleteByKey0 = NULL;
static pfn_FwpmFilterAdd0 pFwpmFilterAdd0 = NULL;

static HANDLE g_hEngine = NULL;
static BOOL g_wfp_active = FALSE;

static BOOL load_wfp_dll_functions(void) {
    if (g_hWfpDll) return TRUE;
    g_hWfpDll = LoadLibraryA("fwpuclnt.dll");
    if (!g_hWfpDll) {
        g_hWfpDll = LoadLibraryA("fwpapi.dll");
    }
    if (!g_hWfpDll) return FALSE;

    pFwpmEngineOpen0 = (pfn_FwpmEngineOpen0)GetProcAddress(g_hWfpDll, "FwpmEngineOpen0");
    pFwpmEngineClose0 = (pfn_FwpmEngineClose0)GetProcAddress(g_hWfpDll, "FwpmEngineClose0");
    pFwpmSubLayerAdd0 = (pfn_FwpmSubLayerAdd0)GetProcAddress(g_hWfpDll, "FwpmSubLayerAdd0");
    pFwpmSubLayerDeleteByKey0 = (pfn_FwpmSubLayerDeleteByKey0)GetProcAddress(g_hWfpDll, "FwpmSubLayerDeleteByKey0");
    pFwpmFilterAdd0 = (pfn_FwpmFilterAdd0)GetProcAddress(g_hWfpDll, "FwpmFilterAdd0");

    return (pFwpmEngineOpen0 && pFwpmEngineClose0 && pFwpmSubLayerAdd0 && pFwpmFilterAdd0);
}

BOOL wfp_init(void) {
    if (g_wfp_active) return TRUE;

    if (!load_wfp_dll_functions()) {
        logger_system("WARN", "WFP system library fwpuclnt.dll not available.");
        return FALSE;
    }

    DWORD dwResult = pFwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_hEngine);
    if (dwResult != ERROR_SUCCESS) {
        if (dwResult == ERROR_ACCESS_DENIED) {
            logger_system("WARN", "WFP Initialization: Access Denied. Run IdentityNet as Administrator to enable WFP firewall filtering.");
        } else {
            logger_system("WARN", "FwpmEngineOpen0 failed with error: 0x%08X", dwResult);
        }
        g_hEngine = NULL;
        g_wfp_active = FALSE;
        return FALSE;
    }

    // Add custom IdentityNet sublayer
    FWPM_SUBLAYER0 subLayer;
    memset(&subLayer, 0, sizeof(subLayer));
    subLayer.subLayerKey = GUID_IDENTITYNET_SUBLAYER;
    subLayer.displayData.name = L"IdentityNet Gateway WFP Sublayer";
    subLayer.displayData.description = L"Enforces Default-Deny Allowlist and Anti-Bypass DNS Filtering";
    subLayer.flags = 0;
    subLayer.weight = 0x7FFF;

    dwResult = pFwpmSubLayerAdd0(g_hEngine, &subLayer, NULL);
    if (dwResult != ERROR_SUCCESS && dwResult != FWP_E_ALREADY_EXISTS) {
        logger_system("WARN", "FwpmSubLayerAdd0 failed with error: 0x%08X", dwResult);
    }

    g_wfp_active = TRUE;
    logger_system("ONLINE", "Windows Filtering Platform (WFP) Firewall Manager ACTIVE.");
    return TRUE;
}

void wfp_cleanup(void) {
    if (g_hEngine && pFwpmEngineClose0) {
        if (pFwpmSubLayerDeleteByKey0) {
            pFwpmSubLayerDeleteByKey0(g_hEngine, &GUID_IDENTITYNET_SUBLAYER);
        }
        pFwpmEngineClose0(g_hEngine);
        g_hEngine = NULL;
    }
    if (g_hWfpDll) {
        FreeLibrary(g_hWfpDll);
        g_hWfpDll = NULL;
    }
    g_wfp_active = FALSE;
    logger_system("INFO", "Cleaned up WFP Firewall engine and filters.");
}

BOOL wfp_is_active(void) {
    return g_wfp_active;
}

BOOL wfp_add_anti_bypass_dns_filter(const char *hotspot_subnet) {
    if (!g_wfp_active || !g_hEngine || !pFwpmFilterAdd0) return FALSE;

    FWPM_FILTER0 filter;
    FWPM_FILTER_CONDITION0 conditions[1];
    memset(&filter, 0, sizeof(filter));
    memset(conditions, 0, sizeof(conditions));

    filter.displayData.name = L"IdentityNet Anti-Bypass DNS Filter";
    filter.displayData.description = L"Blocks direct external DNS queries to 8.8.8.8 / 1.1.1.1";
    filter.layerKey = GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = GUID_IDENTITYNET_SUBLAYER;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.type = FWP_UINT64;

    conditions[0].fieldKey = GUID_FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_UINT16;
    conditions[0].conditionValue.uint16 = 53;

    filter.filterCondition = conditions;
    filter.numFilterConditions = 1;

    UINT64 filterId = 0;
    DWORD dwResult = pFwpmFilterAdd0(g_hEngine, &filter, NULL, &filterId);
    if (dwResult == ERROR_SUCCESS) {
        logger_system("INFO", "Configured WFP Anti-Bypass DNS Protection Filter (FilterID: %llu).", filterId);
        return TRUE;
    }
    return FALSE;
}

BOOL wfp_add_allow_destination_ip(const char *ip_address) {
    if (!g_wfp_active || !g_hEngine || !pFwpmFilterAdd0 || !ip_address) return FALSE;

    FWPM_FILTER0 filter;
    FWPM_FILTER_CONDITION0 conditions[1];
    memset(&filter, 0, sizeof(filter));
    memset(conditions, 0, sizeof(conditions));

    wchar_t name_buf[128];
    swprintf(name_buf, 128, L"IdentityNet Permit IP %hs", ip_address);

    filter.displayData.name = name_buf;
    filter.layerKey = GUID_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = GUID_IDENTITYNET_SUBLAYER;
    filter.action.type = FWP_ACTION_PERMIT;

    conditions[0].fieldKey = GUID_FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_UINT32;
    conditions[0].conditionValue.uint32 = ntohl(inet_addr(ip_address));

    filter.filterCondition = conditions;
    filter.numFilterConditions = 1;

    UINT64 filterId = 0;
    DWORD dwResult = pFwpmFilterAdd0(g_hEngine, &filter, NULL, &filterId);
    if (dwResult == ERROR_SUCCESS) {
        logger_system("INFO", "WFP PERMITTED destination IP '%s' (FilterID: %llu).", ip_address, filterId);
        return TRUE;
    }
    return FALSE;
}

package arp

//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output zsyscall_windows.go syscall.go

//sys getIpNetTable

// DWORD GetIpNetTable(
//   _Out_   PMIB_IPNETTABLE pIpNetTable,
//   _Inout_ PULONG          pdwSize,
//   _In_    BOOL            bOrder
// );

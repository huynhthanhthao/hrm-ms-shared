// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v6.30.2
// source: proto/permission/permission_ext.proto

package permission

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	ExtService_DeleteUserPermsByUserID_FullMethodName = "/permission_proto.ExtService/DeleteUserPermsByUserID"
	ExtService_DeleteUserRolesByUserID_FullMethodName = "/permission_proto.ExtService/DeleteUserRolesByUserID"
	ExtService_UpdateUserPerms_FullMethodName         = "/permission_proto.ExtService/UpdateUserPerms"
	ExtService_UpdateUserRoles_FullMethodName         = "/permission_proto.ExtService/UpdateUserRoles"
	ExtService_GetUserPerms_FullMethodName            = "/permission_proto.ExtService/GetUserPerms"
	ExtService_GetUserRoles_FullMethodName            = "/permission_proto.ExtService/GetUserRoles"
)

// ExtServiceClient is the client API for ExtService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ExtServiceClient interface {
	DeleteUserPermsByUserID(ctx context.Context, in *DeleteUserPermsByUserIDRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	DeleteUserRolesByUserID(ctx context.Context, in *DeleteUserRolesByUserIDRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	UpdateUserPerms(ctx context.Context, in *UpdateUserPermsRequest, opts ...grpc.CallOption) (*UpdateUserPermsResponse, error)
	UpdateUserRoles(ctx context.Context, in *UpdateUserRolesRequest, opts ...grpc.CallOption) (*UpdateUserRolesResponse, error)
	GetUserPerms(ctx context.Context, in *GetUserPermsRequest, opts ...grpc.CallOption) (*GetUserPermsResponse, error)
	GetUserRoles(ctx context.Context, in *GetUserRolesRequest, opts ...grpc.CallOption) (*GetUserRolesResponse, error)
}

type extServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewExtServiceClient(cc grpc.ClientConnInterface) ExtServiceClient {
	return &extServiceClient{cc}
}

func (c *extServiceClient) DeleteUserPermsByUserID(ctx context.Context, in *DeleteUserPermsByUserIDRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, ExtService_DeleteUserPermsByUserID_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *extServiceClient) DeleteUserRolesByUserID(ctx context.Context, in *DeleteUserRolesByUserIDRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, ExtService_DeleteUserRolesByUserID_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *extServiceClient) UpdateUserPerms(ctx context.Context, in *UpdateUserPermsRequest, opts ...grpc.CallOption) (*UpdateUserPermsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(UpdateUserPermsResponse)
	err := c.cc.Invoke(ctx, ExtService_UpdateUserPerms_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *extServiceClient) UpdateUserRoles(ctx context.Context, in *UpdateUserRolesRequest, opts ...grpc.CallOption) (*UpdateUserRolesResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(UpdateUserRolesResponse)
	err := c.cc.Invoke(ctx, ExtService_UpdateUserRoles_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *extServiceClient) GetUserPerms(ctx context.Context, in *GetUserPermsRequest, opts ...grpc.CallOption) (*GetUserPermsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetUserPermsResponse)
	err := c.cc.Invoke(ctx, ExtService_GetUserPerms_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *extServiceClient) GetUserRoles(ctx context.Context, in *GetUserRolesRequest, opts ...grpc.CallOption) (*GetUserRolesResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetUserRolesResponse)
	err := c.cc.Invoke(ctx, ExtService_GetUserRoles_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ExtServiceServer is the server API for ExtService service.
// All implementations must embed UnimplementedExtServiceServer
// for forward compatibility.
type ExtServiceServer interface {
	DeleteUserPermsByUserID(context.Context, *DeleteUserPermsByUserIDRequest) (*emptypb.Empty, error)
	DeleteUserRolesByUserID(context.Context, *DeleteUserRolesByUserIDRequest) (*emptypb.Empty, error)
	UpdateUserPerms(context.Context, *UpdateUserPermsRequest) (*UpdateUserPermsResponse, error)
	UpdateUserRoles(context.Context, *UpdateUserRolesRequest) (*UpdateUserRolesResponse, error)
	GetUserPerms(context.Context, *GetUserPermsRequest) (*GetUserPermsResponse, error)
	GetUserRoles(context.Context, *GetUserRolesRequest) (*GetUserRolesResponse, error)
	mustEmbedUnimplementedExtServiceServer()
}

// UnimplementedExtServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedExtServiceServer struct{}

func (UnimplementedExtServiceServer) DeleteUserPermsByUserID(context.Context, *DeleteUserPermsByUserIDRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUserPermsByUserID not implemented")
}
func (UnimplementedExtServiceServer) DeleteUserRolesByUserID(context.Context, *DeleteUserRolesByUserIDRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUserRolesByUserID not implemented")
}
func (UnimplementedExtServiceServer) UpdateUserPerms(context.Context, *UpdateUserPermsRequest) (*UpdateUserPermsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUserPerms not implemented")
}
func (UnimplementedExtServiceServer) UpdateUserRoles(context.Context, *UpdateUserRolesRequest) (*UpdateUserRolesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUserRoles not implemented")
}
func (UnimplementedExtServiceServer) GetUserPerms(context.Context, *GetUserPermsRequest) (*GetUserPermsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUserPerms not implemented")
}
func (UnimplementedExtServiceServer) GetUserRoles(context.Context, *GetUserRolesRequest) (*GetUserRolesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUserRoles not implemented")
}
func (UnimplementedExtServiceServer) mustEmbedUnimplementedExtServiceServer() {}
func (UnimplementedExtServiceServer) testEmbeddedByValue()                    {}

// UnsafeExtServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ExtServiceServer will
// result in compilation errors.
type UnsafeExtServiceServer interface {
	mustEmbedUnimplementedExtServiceServer()
}

func RegisterExtServiceServer(s grpc.ServiceRegistrar, srv ExtServiceServer) {
	// If the following call pancis, it indicates UnimplementedExtServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&ExtService_ServiceDesc, srv)
}

func _ExtService_DeleteUserPermsByUserID_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteUserPermsByUserIDRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExtServiceServer).DeleteUserPermsByUserID(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExtService_DeleteUserPermsByUserID_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExtServiceServer).DeleteUserPermsByUserID(ctx, req.(*DeleteUserPermsByUserIDRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExtService_DeleteUserRolesByUserID_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteUserRolesByUserIDRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExtServiceServer).DeleteUserRolesByUserID(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExtService_DeleteUserRolesByUserID_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExtServiceServer).DeleteUserRolesByUserID(ctx, req.(*DeleteUserRolesByUserIDRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExtService_UpdateUserPerms_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateUserPermsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExtServiceServer).UpdateUserPerms(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExtService_UpdateUserPerms_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExtServiceServer).UpdateUserPerms(ctx, req.(*UpdateUserPermsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExtService_UpdateUserRoles_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateUserRolesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExtServiceServer).UpdateUserRoles(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExtService_UpdateUserRoles_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExtServiceServer).UpdateUserRoles(ctx, req.(*UpdateUserRolesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExtService_GetUserPerms_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUserPermsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExtServiceServer).GetUserPerms(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExtService_GetUserPerms_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExtServiceServer).GetUserPerms(ctx, req.(*GetUserPermsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExtService_GetUserRoles_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetUserRolesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExtServiceServer).GetUserRoles(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExtService_GetUserRoles_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExtServiceServer).GetUserRoles(ctx, req.(*GetUserRolesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ExtService_ServiceDesc is the grpc.ServiceDesc for ExtService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ExtService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "permission_proto.ExtService",
	HandlerType: (*ExtServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "DeleteUserPermsByUserID",
			Handler:    _ExtService_DeleteUserPermsByUserID_Handler,
		},
		{
			MethodName: "DeleteUserRolesByUserID",
			Handler:    _ExtService_DeleteUserRolesByUserID_Handler,
		},
		{
			MethodName: "UpdateUserPerms",
			Handler:    _ExtService_UpdateUserPerms_Handler,
		},
		{
			MethodName: "UpdateUserRoles",
			Handler:    _ExtService_UpdateUserRoles_Handler,
		},
		{
			MethodName: "GetUserPerms",
			Handler:    _ExtService_GetUserPerms_Handler,
		},
		{
			MethodName: "GetUserRoles",
			Handler:    _ExtService_GetUserRoles_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/permission/permission_ext.proto",
}

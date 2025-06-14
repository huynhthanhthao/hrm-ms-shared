// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v6.30.2
// source: proto/hr/hr_ext.proto

package hr

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
	ExtService_GetEmployeeByUserId_FullMethodName    = "/hr_proto.ExtService/GetEmployeeByUserId"
	ExtService_DeleteEmployeeByUserId_FullMethodName = "/hr_proto.ExtService/DeleteEmployeeByUserId"
)

// ExtServiceClient is the client API for ExtService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ExtServiceClient interface {
	GetEmployeeByUserId(ctx context.Context, in *GetEmployeeByUserIdRequest, opts ...grpc.CallOption) (*Employee, error)
	DeleteEmployeeByUserId(ctx context.Context, in *DeleteEmployeeByUserIdRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type extServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewExtServiceClient(cc grpc.ClientConnInterface) ExtServiceClient {
	return &extServiceClient{cc}
}

func (c *extServiceClient) GetEmployeeByUserId(ctx context.Context, in *GetEmployeeByUserIdRequest, opts ...grpc.CallOption) (*Employee, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(Employee)
	err := c.cc.Invoke(ctx, ExtService_GetEmployeeByUserId_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *extServiceClient) DeleteEmployeeByUserId(ctx context.Context, in *DeleteEmployeeByUserIdRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, ExtService_DeleteEmployeeByUserId_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ExtServiceServer is the server API for ExtService service.
// All implementations must embed UnimplementedExtServiceServer
// for forward compatibility.
type ExtServiceServer interface {
	GetEmployeeByUserId(context.Context, *GetEmployeeByUserIdRequest) (*Employee, error)
	DeleteEmployeeByUserId(context.Context, *DeleteEmployeeByUserIdRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedExtServiceServer()
}

// UnimplementedExtServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedExtServiceServer struct{}

func (UnimplementedExtServiceServer) GetEmployeeByUserId(context.Context, *GetEmployeeByUserIdRequest) (*Employee, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEmployeeByUserId not implemented")
}
func (UnimplementedExtServiceServer) DeleteEmployeeByUserId(context.Context, *DeleteEmployeeByUserIdRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteEmployeeByUserId not implemented")
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

func _ExtService_GetEmployeeByUserId_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetEmployeeByUserIdRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExtServiceServer).GetEmployeeByUserId(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExtService_GetEmployeeByUserId_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExtServiceServer).GetEmployeeByUserId(ctx, req.(*GetEmployeeByUserIdRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExtService_DeleteEmployeeByUserId_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteEmployeeByUserIdRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExtServiceServer).DeleteEmployeeByUserId(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: ExtService_DeleteEmployeeByUserId_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExtServiceServer).DeleteEmployeeByUserId(ctx, req.(*DeleteEmployeeByUserIdRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ExtService_ServiceDesc is the grpc.ServiceDesc for ExtService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ExtService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "hr_proto.ExtService",
	HandlerType: (*ExtServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetEmployeeByUserId",
			Handler:    _ExtService_GetEmployeeByUserId_Handler,
		},
		{
			MethodName: "DeleteEmployeeByUserId",
			Handler:    _ExtService_DeleteEmployeeByUserId_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/hr/hr_ext.proto",
}

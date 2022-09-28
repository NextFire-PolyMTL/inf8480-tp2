/*
 *
 * Copyright 2015 gRPC authors.
 * INF8480 TP2 v4 A20 Polytechnique Montréal
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
 
#include <iostream>
#include <memory>
#include <string>

#include <grpc++/grpc++.h>
#include "operation.grpc.pb.h"

#define TRACEPOINT_DEFINE

#include "lttng-traces/grpc_tracing.h"


using grpc::Channel;
using grpc::ChannelArguments;
using grpc::ClientContext;
using grpc::Status;
using operation::Operation;
using operation::OperationRequest;
using operation::OperationReply;

class OperationManager {
public:
    OperationManager(std::shared_ptr <Channel> channel)
            : stub_(Operation::NewStub(channel)) {}

    // Assembles the client's payload, sends it and presents the response back from the server
    std::string ProcessOperation(const std::string &task) {
        char cstr1[task.size() + 1];
        strcpy(cstr1, task.c_str());
        tracepoint(grpc_tracing, manager_send, cstr1);//DO NOT MODIFY
        OperationRequest request;
        request.set_task(task);// Data we are sending to the server.
        OperationReply reply; // Container for the data we expect from the server.

        // Context for the client. It could be used to convey extra information to the server and/or tweak certain RPC behaviors.
        ClientContext context;

//TODO : send the gRPC call

        char cstr2[reply.message().size() + 1];
        strcpy(cstr2, reply.message().c_str());
        tracepoint(grpc_tracing, manager_recv, cstr2);//DO NOT MODIFY
        // Act upon its status.
        if (status.ok()) {
            return reply.message();
        } else {
            std::cout << status.error_code() << ": " << status.error_message()
                      << std::endl;
            return 0;
        }
    }

private:
    std::unique_ptr <Operation::Stub> stub_;
};

int main(int argc, char **argv) {
    // Instantiate the client. It requires a channel, out of which the actual RPCs  are created.
    //This channel models a connection to an endpoint
    ChannelArguments args;
    // Set the load balancing policy for the channel.
    args.SetLoadBalancingPolicyName("round_robin");

    OperationManager manager(grpc::CreateCustomChannel(
            "localhost:50051", grpc::InsecureChannelCredentials(), args));

//TODO : modify this code to take the task as command line parameter

    
    std::string task("tache envoyee");
    std::string reply = manager.ProcessOperation(task);
    std::cout << "Reply from server : " << reply << std::endl;

    return 0;
}

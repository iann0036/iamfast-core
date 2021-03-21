export interface IAMDef {
    readonly prefix: string;
    readonly conditions: IAMDefCondition[];
    readonly privileges: IAMDefPrivilege[];
    readonly resources: IAMDefResource[];
    readonly serviceName: string;
}

export interface IAMDefCondition {
    readonly condition: string;
    readonly description: string;
    readonly type: string;
}

export interface IAMDefPrivilege {
    readonly accessLevel: string;
    readonly description: string;
    readonly privilege: string;
    readonly resourceTypes: IAMDefPrivilegeResourceType[];
}

export interface IAMDefPrivilegeResourceType {
    readonly conditionKeys: string[];
    readonly dependentActions: string[];
    readonly resourceType: string;
}

export interface IAMDefResource {
    readonly arn: string;
    readonly conditionKeys: string[];
    readonly resource: string;
}

export interface Mappings {
    readonly sdkPermissionlessAction: string[];
    readonly sdkMethodIamMappings: { [key: string]: MethodMapping[] };
    readonly sdkServiceMappings: { [key: string]: string };
}

export interface MethodMapping {
    readonly action: string;
    readonly resourceMappings: { [key: string]: ResourceMappingOptions };
}

export interface ResourceMappingOptions {
    readonly template: string;
}

export interface TrackedCall {
    readonly service: string;
    readonly method: string;
    readonly params: { [key: string]: string };
}

export interface Priv {
    readonly sarpriv: IAMDefPrivilege;
    readonly mappedpriv: MethodMapping;
}

export interface PolicyPriv {
    readonly action: string;
    readonly explanation: string;
    readonly resource: string[];
}

export class IAMFastCore {
    private aws_partition: string;
    private aws_region: string;
    private aws_accountid: string;
    private iamdef: IAMDef[];
    private mappings: Mappings;

    public constructor(iamdef: string, mappings: string, aws_partition?: string, aws_region?: string, aws_accountid?: string) {
        this.iamdef = JSON.parse(iamdef);
        this.mappings = JSON.parse(mappings);
        this.aws_partition = aws_partition || 'aws';
        this.aws_region = aws_region || 'us-east-1';
        this.aws_accountid = aws_accountid || '123456789012';
    }

    private subSARARN(arn: string, params: { [key: string]: string }, mapped_priv: MethodMapping) {
        if (mapped_priv && mapped_priv.resourceMappings) {
            for (let param of Object.keys(mapped_priv.resourceMappings)) {
                let r = new RegExp("\\$\\{" + param + "\\}", "gi");
                arn = arn.replace(r, mapped_priv.resourceMappings[param].template);
            }
        }
    
        for (let param of Object.keys(params)) {
            let r = new RegExp("\\$\\{" + param + "\\}", "gi");
            arn = arn.replace(r, params[param]);
        }
    
        arn = arn.replace(/\$\{Partition\}/g, this.aws_partition);
        arn = arn.replace(/\$\{Region\}/g, this.aws_region);
        arn = arn.replace(/\$\{Account\}/g, this.aws_accountid);
    
        arn = arn.replace(/\$\{.*\}/g, "*");
    
        return arn;
    }

    private toIAMPolicy(privs: PolicyPriv[]) {
        interface IAMPolicy {
            Version: string;
            Statement: IAMPolicyStatement[];
        }
        
        interface IAMPolicyStatement {
            Effect: string;
            Action: string | string[];
            Resource: string | string[];
        }

        let policy: IAMPolicy = {
            'Version': '2012-10-17',
            'Statement': []
        };
    
        for (let priv of privs) {
            policy.Statement.push({
                'Effect': 'Allow',
                'Action': priv.action,
                'Resource': priv.resource
            })
        }
    
        return JSON.stringify(policy, null, 4);
    }
    
    private mapServicePrefix(prefix: string) {
        if (this.mappings.sdkServiceMappings[prefix]) {
            return this.mappings.sdkServiceMappings[prefix];
        }
    
        return prefix;
    }

    private mapCallToPrivilegeArray(service: IAMDef, call: TrackedCall) {
        let lower_priv = call.service.toLowerCase() + "." + call.method.toLowerCase();
    
        let privileges: Priv[] = [];
    
        // check if it's in the mapping
        for (let mappingkey of Object.keys(this.mappings.sdkMethodIamMappings)) {
            if (lower_priv == mappingkey.toLowerCase()) {
                for (var mapped_priv of this.mappings.sdkMethodIamMappings[mappingkey]) {
                    for (let privilege of service.privileges) {
                        if (this.mapServicePrefix(service.prefix)!.toLowerCase() + ":" + privilege.privilege.toLowerCase() == mapped_priv.action.toLowerCase()) {
                            privileges.push({
                                sarpriv: privilege,
                                mappedpriv: mapped_priv
                            });
                            break;
                        }
                    }
                }
    
                return privileges;
            }
        }
    
        // last resort check the SAR directly
        if (!privileges.length) {
            for (let privilege of service.privileges) {
                if (call.method.toLowerCase() == privilege.privilege.toLowerCase()) {
                    return [{
                        'sarpriv': privilege,
                        'mappedpriv': null
                    }];
                }
            }
        }
    
        return [];
    }

    public generateIAMPolicy(tracked_calls: TrackedCall[]) {
        let privs: PolicyPriv[] = [];
    
        for (let tracked_call of tracked_calls) {
            let found_match = false;
    
            for (let service of this.iamdef) {
                if (this.mapServicePrefix(service.prefix)!.toLowerCase() == tracked_call.service.toLowerCase()) {
                    let privilege_array = this.mapCallToPrivilegeArray(service, tracked_call);
    
                    for (let privilege of privilege_array) {
                        found_match = true;
    
                        let resource_arns = [];
    
                        if (privilege.sarpriv.resourceTypes.length) {
                            for (let resource_type of privilege.sarpriv.resourceTypes) {
                                for (let resource of service.resources) {
                                    if (resource.resource.toLowerCase() == resource_type.resourceType.replace(/\*/g, "").toLowerCase() && resource.resource != "") {
                                        let subbed_arn = this.subSARARN(resource.arn, tracked_call.params, privilege.mappedpriv!);
                                        if (resource_type.resourceType.endsWith("*") || !subbed_arn.endsWith("*")) {
                                            resource_arns.push(subbed_arn);
                                        }
                                    }
                                }
                            }
                        }
    
                        if (resource_arns.length == 0) {
                            resource_arns = ["*"];
                        }
    
                        privs.push({
                            action: this.mapServicePrefix(service.prefix) + ":" + privilege.sarpriv.privilege,
                            explanation: privilege.sarpriv.description,
                            resource: resource_arns
                        });
                    }
                }
            }
    
            if (
                !found_match && ![
                    "endpoint",
                    "defineservice",
                    "makerequest",
                    "makeunauthenticatedrequest",
                    "setuprequestlisteners",
                    "waitfor"
                ].includes(tracked_call.method.toLowerCase()) // generic service methods
            ) {
                throw "WARNING: Could not find privilege match for " + tracked_call.service.toLowerCase() + ":" + tracked_call.method;
            }
        }
    
        return this.toIAMPolicy(privs);
    }
}


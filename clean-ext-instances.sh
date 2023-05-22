#!/usr/bin/env bash

ECS_CLUSTER="user-workflow-qa"

counter=0
while true; do
  unset instance_arns
  printf "==> Fetching instance list..\n"
  instance_arns="$(aws ecs list-container-instances \
    --cluster "${ECS_CLUSTER}" \
    --query "containerInstanceArns[]" \
    | cut -d '/' -f3 \
    | tail -n100 2>/dev/null)"

  instances="$(aws ecs describe-container-instances \
    --cluster "${ECS_CLUSTER}" \
    --container-instances $instance_arns \
    | yq '.containerInstances[] | select(.ec2InstanceId | test("mi-")) | .containerInstanceArn' \
    | cut -d '/' -f3)"

  if [[ -z "$instances" ]]; then
    (( counter == 0 )) && printf "==> External instances not found!\n"
    (( counter > 0 )) && printf "==> Number of deleted instances: %s" "$((counter))"
    exit 0
  fi

  (( counter == 0 )) && printf "==> Starting removal process..\n"
  (( counter > 0 )) && printf "==> Continuing removal process..\n"
  while read -r line; do
    [[ -z "$instances" ]] && break
    printf "* %s\n" "$line"
    aws ecs deregister-container-instance \
      --no-cli-pager \
      --cluster "${ECS_CLUSTER}" \
      --container-instance "$line" > /dev/null
    counter=$((counter+1))
  done < <(echo -e "$instances")
done

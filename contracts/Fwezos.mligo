# 1 "./single_asset/ligo/src/fa2_single_token.mligo"
(**
Implementation of the FA2 interface for the single token contract.
 *)






# 1 "./single_asset/ligo/src/../fa2/fa2_interface.mligo" 1



type token_id = nat

type transfer_destination = {
  to_ : address;
  token_id : token_id;
  amount : nat;
}

type transfer_destination_michelson = transfer_destination michelson_pair_right_comb

type transfer = {
  from_ : address;
  txs : transfer_destination list;
}

type transfer_aux = {
  from_ : address;
  txs : transfer_destination_michelson list;
}

type transfer_michelson = transfer_aux michelson_pair_right_comb

type balance_of_request = {
  owner : address;
  token_id : token_id;
}

type balance_of_request_michelson = balance_of_request michelson_pair_right_comb

type balance_of_response = {
  request : balance_of_request;
  balance : nat;
}

type balance_of_response_aux = {
  request : balance_of_request_michelson;
  balance : nat;
}

type balance_of_response_michelson = balance_of_response_aux michelson_pair_right_comb

type balance_of_param = {
  requests : balance_of_request list;
  callback : (balance_of_response_michelson list) contract;
}

type balance_of_param_aux = {
  requests : balance_of_request_michelson list;
  callback : (balance_of_response_michelson list) contract;
}

type balance_of_param_michelson = balance_of_param_aux michelson_pair_right_comb

type operator_param = {
  owner : address;
  operator : address;
  token_id: token_id;
}

type operator_param_michelson = operator_param michelson_pair_right_comb

type update_operator =
  | Add_operator_p of operator_param
  | Remove_operator_p of operator_param

type update_operator_aux =
  | Add_operator of operator_param_michelson
  | Remove_operator of operator_param_michelson

type update_operator_michelson = update_operator_aux michelson_or_right_comb

type token_metadata = {
  token_id : token_id;
  symbol : string;
  name : string;
  decimals : nat;
  extras : (string, string) map;
}

type token_metadata_michelson = token_metadata michelson_pair_right_comb

type token_metadata_param = {
  token_ids : token_id list;
  handler : (token_metadata_michelson list) -> unit;
}

type token_metadata_param_michelson = token_metadata_param michelson_pair_right_comb

type fa2_entry_points =
  | Transfer of transfer_michelson list
  | Balance_of of balance_of_param_michelson
  | Update_operators of update_operator_michelson list
  | Token_metadata_registry of address contract
  | Mint_tokens of unit
  | Redeem_tokens of nat


type fa2_token_metadata =
  | Token_metadata of token_metadata_param_michelson

(* permission policy definition *)

type operator_transfer_policy =
  | No_transfer
  | Owner_transfer
  | Owner_or_operator_transfer

type operator_transfer_policy_michelson = operator_transfer_policy michelson_or_right_comb

type owner_hook_policy =
  | Owner_no_hook
  | Optional_owner_hook
  | Required_owner_hook

type owner_hook_policy_michelson = owner_hook_policy michelson_or_right_comb

type custom_permission_policy = {
  tag : string;
  config_api: address option;
}

type custom_permission_policy_michelson = custom_permission_policy michelson_pair_right_comb

type permissions_descriptor = {
  operator : operator_transfer_policy;
  receiver : owner_hook_policy;
  sender : owner_hook_policy;
  custom : custom_permission_policy option;
}

type permissions_descriptor_aux = {
  operator : operator_transfer_policy_michelson;
  receiver : owner_hook_policy_michelson;
  sender : owner_hook_policy_michelson;
  custom : custom_permission_policy_michelson option;
}

type permissions_descriptor_michelson = permissions_descriptor_aux michelson_pair_right_comb

(* permissions descriptor entrypoint
type fa2_entry_points_custom =
  ...
  | Permissions_descriptor of permissions_descriptor_michelson contract

*)


type transfer_destination_descriptor = {
  to_ : address option;
  token_id : token_id;
  amount : nat;
}

type transfer_destination_descriptor_michelson =
  transfer_destination_descriptor michelson_pair_right_comb

type transfer_descriptor = {
  from_ : address option;
  txs : transfer_destination_descriptor list
}

type transfer_descriptor_aux = {
  from_ : address option;
  txs : transfer_destination_descriptor_michelson list
}

type transfer_descriptor_michelson = transfer_descriptor_aux michelson_pair_right_comb

type transfer_descriptor_param = {
  batch : transfer_descriptor list;
  operator : address;
}

type transfer_descriptor_param_aux = {
  batch : transfer_descriptor_michelson list;
  operator : address;
}

type transfer_descriptor_param_michelson = transfer_descriptor_param_aux michelson_pair_right_comb
(*
Entrypoints for sender/receiver hooks

type fa2_token_receiver =
  ...
  | Tokens_received of transfer_descriptor_param_michelson

type fa2_token_sender =
  ...
  | Tokens_sent of transfer_descriptor_param_michelson
*)



# 10 "./single_asset/ligo/src/fa2_single_token.mligo" 2

# 1 "./single_asset/ligo/src/../fa2/fa2_errors.mligo" 1



(** One of the specified `token_id`s is not defined within the FA2 contract *)
let fa2_token_undefined = "FA2_TOKEN_UNDEFINED" 
(** 
A token owner does not have sufficient balance to transfer tokens from
owner's account 
*)
let fa2_insufficient_balance = "FA2_INSUFFICIENT_BALANCE"
(** A transfer failed because of `operator_transfer_policy == No_transfer` *)
let fa2_tx_denied = "FA2_TX_DENIED"
(** 
A transfer failed because `operator_transfer_policy == Owner_transfer` and it is
initiated not by the token owner 
*)
let fa2_not_owner = "FA2_NOT_OWNER"
(**
A transfer failed because `operator_transfer_policy == Owner_or_operator_transfer`
and it is initiated neither by the token owner nor a permitted operator
 *)
let fa2_not_operator = "FA2_NOT_OPERATOR"
(** 
`update_operators` entrypoint is invoked and `operator_transfer_policy` is
`No_transfer` or `Owner_transfer`
*)
let fa2_operators_not_supported = "FA2_OPERATORS_UNSUPPORTED"
(**
Receiver hook is invoked and failed. This error MUST be raised by the hook
implementation
 *)
let fa2_receiver_hook_failed = "FA2_RECEIVER_HOOK_FAILED"
(**
Sender hook is invoked and failed. This error MUST be raised by the hook
implementation
 *)
let fa2_sender_hook_failed = "FA2_SENDER_HOOK_FAILED"
(**
Receiver hook is required by the permission behavior, but is not implemented by
a receiver contract
 *)
let fa2_receiver_hook_undefined = "FA2_RECEIVER_HOOK_UNDEFINED"
(**
Sender hook is required by the permission behavior, but is not implemented by
a sender contract
 *)
let fa2_sender_hook_undefined = "FA2_SENDER_HOOK_UNDEFINED"



# 11 "./single_asset/ligo/src/fa2_single_token.mligo" 2

# 1 "./single_asset/ligo/src/../fa2/lib/fa2_convertors.mligo" 1
(**
Helper function to convert FA2 entrypoints input parameters between their
Michelson and internal LIGO representation.

FA2 contract implementation must conform to the Michelson entrypoints interface
outlined in the FA2 standard for interoperability with other contracts and off-chain
tools.
 *)





# 1 "./single_asset/ligo/src/../fa2/lib/../fa2_interface.mligo" 1




































































































































































































# 14 "./single_asset/ligo/src/../fa2/lib/fa2_convertors.mligo" 2

let permissions_descriptor_to_michelson (d : permissions_descriptor)
    : permissions_descriptor_michelson =
  let aux : permissions_descriptor_aux = {
    operator = Layout.convert_to_right_comb d.operator;
    receiver = Layout.convert_to_right_comb d.receiver;
    sender = Layout.convert_to_right_comb d.sender;
    custom = match d.custom with
    | None -> (None : custom_permission_policy_michelson option)
    | Some c -> Some (Layout.convert_to_right_comb c)
  } in
  Layout.convert_to_right_comb (aux : permissions_descriptor_aux)

let transfer_descriptor_to_michelson (p : transfer_descriptor) : transfer_descriptor_michelson =
  let aux : transfer_descriptor_aux = {
    from_ = p.from_;
    txs = List.map 
      (fun (tx : transfer_destination_descriptor) ->
        Layout.convert_to_right_comb tx
      )
      p.txs;
  } in
  Layout.convert_to_right_comb (aux : transfer_descriptor_aux)

let transfer_descriptor_param_to_michelson (p : transfer_descriptor_param)
    : transfer_descriptor_param_michelson =
  let aux : transfer_descriptor_param_aux = {
    operator = p.operator;
    batch = List.map  transfer_descriptor_to_michelson p.batch;
  } in
  Layout.convert_to_right_comb (aux : transfer_descriptor_param_aux)

let transfer_descriptor_from_michelson (p : transfer_descriptor_michelson) : transfer_descriptor =
  let aux : transfer_descriptor_aux = Layout.convert_from_right_comb p in
  {
    from_ = aux.from_;
    txs = List.map
      (fun (txm : transfer_destination_descriptor_michelson) ->
        let tx : transfer_destination_descriptor =
          Layout.convert_from_right_comb txm in
        tx
      )
      aux.txs;
  }

let transfer_descriptor_param_from_michelson (p : transfer_descriptor_param_michelson)
    : transfer_descriptor_param =
  let aux : transfer_descriptor_param_aux = Layout.convert_from_right_comb p in
  let b : transfer_descriptor list =
    List.map transfer_descriptor_from_michelson aux.batch
  in
  {
    operator = aux.operator;
    batch = b;
  }

let transfer_from_michelson (txm : transfer_michelson) : transfer =
  let aux : transfer_aux = Layout.convert_from_right_comb txm in 
  {
    from_ = aux.from_;
    txs = List.map
      (fun (txm : transfer_destination_michelson) ->
        let tx : transfer_destination = Layout.convert_from_right_comb txm in
        tx
      )
      aux.txs;
  }

let transfers_from_michelson (txsm : transfer_michelson list) : transfer list =
  List.map transfer_from_michelson txsm

let transfer_to_michelson (tx : transfer) : transfer_michelson =
  let aux : transfer_aux = {
    from_ = tx.from_;
    txs = List.map 
      (fun (tx: transfer_destination) -> 
        let t : transfer_destination_michelson = Layout.convert_to_right_comb tx in
        t
      ) tx.txs;
  } in
  Layout.convert_to_right_comb (aux : transfer_aux)

let transfers_to_michelson (txs : transfer list) : transfer_michelson list =
  List.map transfer_to_michelson txs

let operator_param_from_michelson (p : operator_param_michelson) : operator_param =
  let op : operator_param = Layout.convert_from_right_comb p in
  op

let operator_param_to_michelson (p : operator_param) : operator_param_michelson =
  Layout.convert_to_right_comb p

let operator_update_from_michelson (uom : update_operator_michelson) : update_operator =
    let aux : update_operator_aux = Layout.convert_from_right_comb uom in
    match aux with
    | Add_operator opm -> Add_operator_p (operator_param_from_michelson opm)
    | Remove_operator opm -> Remove_operator_p (operator_param_from_michelson opm)

let operator_update_to_michelson (uo : update_operator) : update_operator_michelson =
    let aux = match uo with
    | Add_operator_p op -> Add_operator (operator_param_to_michelson op)
    | Remove_operator_p op -> Remove_operator (operator_param_to_michelson op)
    in
    Layout.convert_to_right_comb aux

let operator_updates_from_michelson (updates_michelson : update_operator_michelson list)
    : update_operator list =
  List.map operator_update_from_michelson updates_michelson

let balance_of_param_from_michelson (p : balance_of_param_michelson) : balance_of_param =
  let aux : balance_of_param_aux = Layout.convert_from_right_comb p in
  let requests = List.map 
    (fun (rm : balance_of_request_michelson) ->
      let r : balance_of_request = Layout.convert_from_right_comb rm in
      r
    )
    aux.requests 
  in
  {
    requests = requests;
    callback = aux.callback;
  } 

let balance_of_param_to_michelson (p : balance_of_param) : balance_of_param_michelson =
  let aux : balance_of_param_aux = {
    requests = List.map 
      (fun (r : balance_of_request) -> Layout.convert_to_right_comb r)
      p.requests;
    callback = p.callback;
  } in
  Layout.convert_to_right_comb (aux : balance_of_param_aux)

let balance_of_response_to_michelson (r : balance_of_response) : balance_of_response_michelson =
  let aux : balance_of_response_aux = {
    request = Layout.convert_to_right_comb r.request;
    balance = r.balance;
  } in
  Layout.convert_to_right_comb (aux : balance_of_response_aux)

let balance_of_response_from_michelson (rm : balance_of_response_michelson) : balance_of_response =
  let aux : balance_of_response_aux = Layout.convert_from_right_comb rm in
  let request : balance_of_request = Layout.convert_from_right_comb aux.request in
  {
    request = request;
    balance = aux.balance;
  }

let token_metas_to_michelson (ms : token_metadata list) : token_metadata_michelson list =
  List.map
    ( fun (m : token_metadata) ->
      let mm : token_metadata_michelson = Layout.convert_to_right_comb m in
      mm
    ) ms


# 12 "./single_asset/ligo/src/fa2_single_token.mligo" 2

# 1 "./single_asset/ligo/src/../fa2/lib/fa2_operator_lib.mligo" 1
(** 
Reference implementation of the FA2 operator storage, config API and 
helper functions 
*)





# 1 "./single_asset/ligo/src/../fa2/lib/fa2_convertors.mligo" 1
(**
Helper function to convert FA2 entrypoints input parameters between their
Michelson and internal LIGO representation.

FA2 contract implementation must conform to the Michelson entrypoints interface
outlined in the FA2 standard for interoperability with other contracts and off-chain
tools.
 *)
































































































































































# 10 "./single_asset/ligo/src/../fa2/lib/fa2_operator_lib.mligo" 2

# 1 "./single_asset/ligo/src/../fa2/lib/../fa2_errors.mligo" 1


















































# 11 "./single_asset/ligo/src/../fa2/lib/fa2_operator_lib.mligo" 2

(** 
(owner, operator, token_id) -> unit
To be part of FA2 storage to manage permitted operators
*)
type operator_storage = ((address * (address * token_id)), unit) big_map

(** 
  Updates operator storage using an `update_operator` command.
  Helper function to implement `Update_operators` FA2 entrypoint
*)
let update_operators (update, storage : update_operator * operator_storage)
    : operator_storage =
  match update with
  | Add_operator_p op -> 
    Big_map.update (op.owner, (op.operator, op.token_id)) (Some unit) storage
  | Remove_operator_p op -> 
    Big_map.remove (op.owner, (op.operator, op.token_id)) storage

(**
Validate if operator update is performed by the token owner.
@param updater an address that initiated the operation; usually `Tezos.sender`.
*)
let validate_update_operators_by_owner (update, updater : update_operator * address)
    : unit =
  let op = match update with
  | Add_operator_p op -> op
  | Remove_operator_p op -> op
  in
  if op.owner = updater then unit else failwith fa2_not_owner

(**
  Generic implementation of the FA2 `%update_operators` entrypoint.
  Assumes that only the token owner can change its operators.
 *)
let fa2_update_operators (updates_michelson, storage
    : (update_operator_michelson list) * operator_storage) : operator_storage =
  let updates = operator_updates_from_michelson updates_michelson in
  let updater = Tezos.sender in
  let process_update = (fun (ops, update : operator_storage * update_operator) ->
    let u = validate_update_operators_by_owner (update, updater) in
    update_operators (update, ops)
  ) in
  List.fold process_update updates storage

(** 
  owner * operator * token_id * ops_storage -> unit
*)
type operator_validator = (address * address * token_id * operator_storage)-> unit

(**
Create an operator validator function based on provided operator policy.
@param tx_policy operator_transfer_policy defining the constrains on who can transfer.
@return (owner, operator, token_id, ops_storage) -> unit
 *)
let make_operator_validator (tx_policy : operator_transfer_policy) : operator_validator =
  let can_owner_tx, can_operator_tx = match tx_policy with
  | No_transfer -> (failwith fa2_tx_denied : bool * bool)
  | Owner_transfer -> true, false
  | Owner_or_operator_transfer -> true, true
  in
  (fun (owner, operator, token_id, ops_storage 
      : address * address * token_id * operator_storage) ->
    if can_owner_tx && owner = operator
    then unit (* transfer by the owner *)
    else if not can_operator_tx
    then failwith fa2_not_owner (* an operator transfer not permitted by the policy *)
    else if Big_map.mem  (owner, (operator, token_id)) ops_storage
    then unit (* the operator is permitted for the token_id *)
    else failwith fa2_not_operator (* the operator is not permitted for the token_id *)
  )

(**
Default implementation of the operator validation function.
The default implicit `operator_transfer_policy` value is `Owner_or_operator_transfer`
 *)
let default_operator_validator : operator_validator =
  (fun (owner, operator, token_id, ops_storage 
      : address * address * token_id * operator_storage) ->
    if owner = operator
    then unit (* transfer by the owner *)
    else if Big_map.mem (owner, (operator, token_id)) ops_storage
    then unit (* the operator is permitted for the token_id *)
    else failwith fa2_not_operator (* the operator is not permitted for the token_id *)
  )

(** 
Validate operators for all transfers in the batch at once
@param tx_policy operator_transfer_policy defining the constrains on who can transfer.
*)
let validate_operator (tx_policy, txs, ops_storage 
    : operator_transfer_policy * (transfer list) * operator_storage) : unit =
  let validator = make_operator_validator tx_policy in
  List.iter (fun (tx : transfer) -> 
    List.iter (fun (dst: transfer_destination) ->
      validator (tx.from_, Tezos.sender, dst.token_id ,ops_storage)
    ) tx.txs
  ) txs



# 13 "./single_asset/ligo/src/fa2_single_token.mligo" 2

# 1 "./single_asset/ligo/src/../fa2/lib/fa2_owner_hooks_lib.mligo" 1



(** 
Generic implementation of the permission logic for sender and receiver hooks. 
Actual behavior is driven by a `permissions_descriptor`.
To be used in FA2 and/or FA2 permission transfer hook contract implementation
which supports sender/receiver hooks.
*)


# 1 "./single_asset/ligo/src/../fa2/lib/../fa2_interface.mligo" 1




































































































































































































# 12 "./single_asset/ligo/src/../fa2/lib/fa2_owner_hooks_lib.mligo" 2

# 1 "./single_asset/ligo/src/../fa2/lib/../fa2_errors.mligo" 1


















































# 13 "./single_asset/ligo/src/../fa2/lib/fa2_owner_hooks_lib.mligo" 2

type get_owners = transfer_descriptor -> (address option) list

type hook_entry_point = transfer_descriptor_param_michelson contract

type hook_result =
  | Hook_entry_point of hook_entry_point
  | Hook_undefined of string

type to_hook = address -> hook_result

(* type transfer_hook_params = {
  ligo_param : transfer_descriptor_param;
  michelson_param : transfer_descriptor_param_michelson;
} *)

(**
Extracts a set of unique `from_` or `to_` addresses from the transfer batch.
@param batch transfer batch
@param get_owner selector of `from_` or `to_` addresses from each individual `transfer_descriptor`
 *)
let get_owners_from_batch (batch, get_owners : (transfer_descriptor list) * get_owners) : address set =
  List.fold 
    (fun (acc, tx : (address set) * transfer_descriptor) ->
      let owners = get_owners tx in
      List.fold 
        (fun (acc, o: (address set) * (address option)) ->
          match o with
          | None -> acc
          | Some a -> Set.add a acc
        )
        owners
        acc
    )
    batch
    (Set.empty : address set)

let validate_owner_hook (p, get_owners, to_hook, is_required :
    transfer_descriptor_param * get_owners * to_hook * bool)
    : hook_entry_point list =
  let owners = get_owners_from_batch (p.batch, get_owners) in
  Set.fold 
    (fun (eps, owner : (hook_entry_point list) * address) ->
      match to_hook owner with
      | Hook_entry_point h -> h :: eps
      | Hook_undefined error ->
        (* owner hook is not implemented by the target contract *)
        if is_required
        then (failwith error : hook_entry_point list) (* owner hook is required: fail *)
        else eps (* owner hook is optional: skip it *)
      )
    owners ([] : hook_entry_point list)

let validate_owner(p, policy, get_owners, to_hook : 
    transfer_descriptor_param * owner_hook_policy * get_owners * to_hook)
    : hook_entry_point list =
  match policy with
  | Owner_no_hook -> ([] : hook_entry_point list)
  | Optional_owner_hook -> validate_owner_hook (p, get_owners, to_hook, false)
  | Required_owner_hook -> validate_owner_hook (p, get_owners, to_hook, true)

(**
Given an address of the token receiver, tries to get an entrypoint for
`fa2_token_receiver` interface.
 *)
let to_receiver_hook : to_hook = fun (a : address) ->
    let c : hook_entry_point option = 
    Operation.get_entrypoint_opt "%tokens_received" a in
    match c with
    | Some c -> Hook_entry_point c
    | None -> Hook_undefined fa2_receiver_hook_undefined

(**
Create a list iof Tezos operations invoking all token receiver contracts that
implement `fa2_token_receiver` interface. Fail if specified `owner_hook_policy`
cannot be met.
 *)
let validate_receivers (p, receiver_policy : transfer_descriptor_param * owner_hook_policy)
    : hook_entry_point list =
  let get_receivers : get_owners = fun (tx : transfer_descriptor) -> 
    List.map (fun (t : transfer_destination_descriptor) -> t.to_ )tx.txs in
  validate_owner (p, receiver_policy, get_receivers, to_receiver_hook)

(**
Given an address of the token sender, tries to get an entrypoint for
`fa2_token_sender` interface.
 *)
let to_sender_hook : to_hook = fun (a : address) ->
    let c : hook_entry_point option = 
    Operation.get_entrypoint_opt "%tokens_sent" a in
    match c with
    | Some c -> Hook_entry_point c
    | None -> Hook_undefined fa2_sender_hook_undefined

(**
Create a list iof Tezos operations invoking all token sender contracts that
implement `fa2_token_sender` interface. Fail if specified `owner_hook_policy`
cannot be met.
 *)
let validate_senders (p, sender_policy : transfer_descriptor_param * owner_hook_policy)
    : hook_entry_point list =
  let get_sender : get_owners = fun (tx : transfer_descriptor) -> [tx.from_] in
  validate_owner (p, sender_policy, get_sender, to_sender_hook)

(**
Generate a list of Tezos operations invoking sender and receiver hooks according to
the policies defined by the permissions descriptor.
To be used in FA2 and/or FA2 transfer hook contract implementation which supports
sender/receiver hooks.
 *)
let get_owner_transfer_hooks (p, descriptor : transfer_descriptor_param * permissions_descriptor)
    : hook_entry_point list =
  let sender_entries = validate_senders (p, descriptor.sender) in
  let receiver_entries = validate_receivers (p, descriptor.receiver) in
  (* merge two lists *)
  List.fold
    (fun (l, ep : (hook_entry_point list) * hook_entry_point) -> ep :: l)
    receiver_entries sender_entries

let transfers_to_descriptors (txs : transfer list) : transfer_descriptor list =
  List.map 
    (fun (tx : transfer) ->
      let txs = List.map 
        (fun (dst : transfer_destination) ->
          {
            to_ = Some dst.to_;
            token_id = dst.token_id;
            amount = dst.amount;
          }
        ) tx.txs in
        {
          from_ = Some tx.from_;
          txs = txs;
        }
    ) txs 

let transfers_to_transfer_descriptor_param
    (txs, operator : (transfer list) * address) : transfer_descriptor_param =
  {
    batch = transfers_to_descriptors txs;
    operator = operator;
  }

(**
 Gets operations to call sender/receiver hook for the specified transfer and
 permission descriptor
 *)
let get_owner_hook_ops_for (tx_descriptor, pd
    : transfer_descriptor_param * permissions_descriptor) : operation list =
  let hook_calls = get_owner_transfer_hooks (tx_descriptor, pd) in
  match hook_calls with
  | [] -> ([] : operation list)
  | h :: t -> 
    let tx_descriptor_michelson = transfer_descriptor_param_to_michelson tx_descriptor in 
    List.map (fun(call: hook_entry_point) -> 
      Operation.transaction tx_descriptor_michelson 0mutez call) 
      hook_calls



# 14 "./single_asset/ligo/src/fa2_single_token.mligo" 2

type ledger = (address, nat) big_map



type single_token_storage = {
  admin: address;
  ledger : ledger;
  operators : operator_storage;
  token_metadata : (nat, token_metadata_michelson) big_map;
  total_supply : nat;
}















# 1 "./single_asset/ligo/src/./mint_tokens.mligo" 1
let mint_tokens (s: single_token_storage): single_token_storage =
    (* User must provide an amount of token to be minted *)
    if Tezos.amount = 0tez
    then (failwith "NO_AMOUNT": single_token_storage)
    else 
        (* checks if user is already present in the ledger *)
        let user_balance = match Big_map.find_opt Tezos.sender s.ledger with
        | Some blc -> blc
        | None -> 0n in
        (* converts amount value in tez into nat *)
        let transferred_amount: nat = Tezos.amount / 1tez in
        (* creates the new balance *)
        let new_balance = user_balance + transferred_amount in
        (* updates the ledger *)
        let new_ledger: ledger = Big_map.update Tezos.sender (Some (new_balance)) s.ledger in
        (* returns the updated storage *)
        { s with ledger = new_ledger }

# 41 "./single_asset/ligo/src/fa2_single_token.mligo" 2

# 1 "./single_asset/ligo/src/./redeem_tokens.mligo" 1
let redeem_tokens ((requested_amount, s): nat * single_token_storage): (operation * single_token_storage) =
    (* There must be no amount attached *)
    if Tezos.amount > 0tez
    then (failwith "NO_AMOUNT_ALLOWED": (operation * single_token_storage))
    else
        (* checks if the sender has an account *)
        let user_balance: nat = match Big_map.find_opt Tezos.sender s.ledger with
        | Some blc -> blc
        | None -> (failwith "NO_BALANCE": nat) in
        (* Checks if the requested amount is not above the available balance *)
        if requested_amount > user_balance
        then (failwith "INSUFFICIENT_BALANCE": (operation * single_token_storage))
        else
            (* Deducts the requested amount from the available balance *)
            let new_balance = user_balance - requested_amount in
            (* Updates the ledger *)
            let new_ledger = Big_map.update Tezos.sender (Some (abs (new_balance))) s.ledger in
            (* Prepares the transfer *)
            let amount_to_send: tez = requested_amount * 1tez in
            let recipient: unit contract = match (Tezos.get_contract_opt Tezos.sender: unit contract option) with 
            | Some contr -> contr
            | None -> (failwith "NO_RECIPIENT_FOUND": unit contract) in
            let op = Tezos.transaction unit amount_to_send recipient in
        
            op, { s with ledger = new_ledger }
# 42 "./single_asset/ligo/src/fa2_single_token.mligo" 2

let get_balance_amt (owner, ledger : address  * ledger) : nat =
  let bal_opt = Big_map.find_opt owner ledger in
  match bal_opt with
  | None -> 0n
  | Some b -> b

let inc_balance (owner, amt, ledger
    : address * nat * ledger) : ledger =
  let bal = get_balance_amt (owner, ledger) in
  let updated_bal = bal + amt in
  if updated_bal = 0n
  then Big_map.remove owner ledger
  else Big_map.update owner (Some updated_bal) ledger 

let dec_balance (owner, amt, ledger
    : address * nat * ledger) : ledger =
  let bal = get_balance_amt (owner, ledger) in
  match Michelson.is_nat (bal - amt) with
  | None -> (failwith fa2_insufficient_balance : ledger)
  | Some new_bal ->
    if new_bal = 0n
    then Big_map.remove owner ledger
    else Big_map.update owner (Some new_bal) ledger

(**
Update leger balances according to the specified transfers. Fails if any of the
permissions or constraints are violated.
@param txs transfers to be applied to the ledger
@param validate_op function that validates of the tokens from the particular owner and token id can be transferred. 
 *)
let transfer (txs, validate_op, ops_storage, ledger
    : (transfer_descriptor list) * operator_validator * operator_storage * ledger)
    : ledger =
  let make_transfer = fun (l, tx : ledger * transfer_descriptor) ->
    List.fold 
      (fun (ll, dst : ledger * transfer_destination_descriptor) ->
        if dst.token_id <> 0n
        then (failwith fa2_token_undefined : ledger)
        else
          let lll = match tx.from_ with
          | None -> ll (* this is a mint transfer. do not need to update `from_` balance *)
          | Some from_ -> 
            let u = validate_op (from_, Tezos.sender, dst.token_id, ops_storage) in
            dec_balance (from_, dst.amount, ll)
          in 
          match dst.to_ with
          | None -> lll (* this is a burn transfer. do not need to update `to_` balance *)
          | Some to_ -> inc_balance(to_, dst.amount, lll) 
      ) tx.txs l
  in    
  List.fold make_transfer txs ledger

(** 
Retrieve the balances for the specified tokens and owners
@return callback operation
*)
let get_balance (p, ledger : balance_of_param * ledger) : operation =
  let to_balance = fun (r : balance_of_request) ->
    if r.token_id <> 0n
    then (failwith fa2_token_undefined : balance_of_response_michelson)
    else
      let bal = get_balance_amt (r.owner, ledger) in
      let response = { request = r; balance = bal; } in
      balance_of_response_to_michelson response
  in
  let responses = List.map to_balance p.requests in
  Operation.transaction responses 0mutez p.callback

(** Validate if all provided token_ids are `0n` and correspond to a single token ID *)
let validate_token_ids (tokens : token_id list) : unit =
  List.iter (fun (id : nat) ->
    if id = 0n then unit else failwith fa2_token_undefined
  ) tokens




let get_owner_hook_ops (tx_descriptors, storage
    : (transfer_descriptor list) * single_token_storage) : operation list =
  ([] : operation list)













let fa2_transfer (tx_descriptors, validate_op, storage
    : (transfer_descriptor list) * operator_validator * single_token_storage)
    : (operation list) * single_token_storage =
  
  let new_ledger = transfer (tx_descriptors, validate_op, storage.operators, storage.ledger) in
  let new_storage = { storage with ledger = new_ledger; } in
  let ops = get_owner_hook_ops (tx_descriptors, storage) in
  ops, new_storage

let main (param, storage : fa2_entry_points * single_token_storage)
    : (operation  list) * single_token_storage =
  match param with
  | Transfer txs_michelson -> 
    (* convert transfer batch into `transfer_descriptor` batch *)
    let txs = transfers_from_michelson txs_michelson in
    let tx_descriptors = transfers_to_descriptors txs in
    (* 
    will validate that a sender is either `from_` parameter of each transfer
    or a permitted operator for the owner `from_` address.
    *)
    fa2_transfer (tx_descriptors, default_operator_validator, storage)

  | Balance_of pm ->
    let p = balance_of_param_from_michelson pm in
    let op = get_balance (p, storage.ledger) in
    [op], storage

  | Update_operators updates_michelson ->
    let new_ops = fa2_update_operators (updates_michelson, storage.operators) in
    let new_storage = { storage with operators = new_ops; } in
    ([] : operation list), new_storage

  | Token_metadata_registry callback ->
    (* the contract storage holds `token_metadata` big_map*)
    let callback_op = Operation.transaction Tezos.self_address 0mutez callback in
    [callback_op], storage

  | Mint_tokens ->
    (* Mint new fwezos tokens *)
    let new_storage = mint_tokens storage in
    ([]: operation list), new_storage

  | Redeem_tokens param ->
    (* Exchange fwezos for XTZ and transfer them *)
    let (op, new_storage) = redeem_tokens (param, storage) in
    [op], new_storage





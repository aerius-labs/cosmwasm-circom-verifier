#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, GetCountResponse, InstantiateMsg, QueryMsg};
use crate::state::{State, STATE};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cw2981-contract-wide";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let state = State {
        count: msg.count,
        owner: info.sender.clone(),
    };
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender)
        .add_attribute("count", msg.count.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Increment {} => execute::increment(deps),
        ExecuteMsg::Reset { count } => execute::reset(deps, info, count),
        ExecuteMsg::Verify { } => execute::verify_proof(),
    }
}

pub mod execute {
    use super::*;

    pub fn increment(deps: DepsMut) -> Result<Response, ContractError> {
        STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
            state.count += 1;
            Ok(state)
        })?;

        Ok(Response::new().add_attribute("action", "increment"))
    }

    pub fn reset(deps: DepsMut, info: MessageInfo, count: i32) -> Result<Response, ContractError> {
        STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
            if info.sender != state.owner {
                return Err(ContractError::Unauthorized {});
            }
            state.count = count;
            Ok(state)
        })?;
        Ok(Response::new().add_attribute("action", "reset"))
    }

    pub fn verify_proof() -> Result<Response, ContractError> {
        let proof_str = r#"
        {
            "pi_a": [
             "15962977779125852550845298703474087870195173890078489799946886499971175404253",
             "588723208915893711962303989315526678440845166135196899676638174889733560253",
             "1"
            ],
            "pi_b": [
             [
              "6615247668750415582590259660774782660724939828234169995610173363470240189045",
              "5049635386497827371757176440203259862950307293996318770245915217953019167274"
             ],
             [
              "5597226962850978137596854145494894011411976105126743556388485237306968024580",
              "13068096530409238868615119301626645993661836686816787458671247680526049782059"
             ],
             [
              "1",
              "0"
             ]
            ],
            "pi_c": [
             "7935403383472026079744518179624272485807915894491875088653094537547814550084",
             "20047960788880824730219597642278782512060853126388848698497858239278917223319",
             "1"
            ],
            "protocol": "groth16",
            "curve": "bn128"
           }
        "#;

        let pub_input_str = r#"
        [
            "33"
        ]
        "#;
        let vkey_str =    r#"
        {
            "protocol": "groth16",
            "curve": "bn128",
            "nPublic": 1,
            "vk_alpha_1": [
             "7678292430642046830947853552693806084820919762284383221814751047549008105112",
             "11664373419350329837776992808963878929870481903189468936076884760736702832350",
             "1"
            ],
            "vk_beta_2": [
             [
              "9287045339795052287936504920314975726295193825206129762115119550163472649682",
              "15494793911117717695138445113541014171780563024127919042491382962676486159832"
             ],
             [
              "17786408745039422411748732632803731314925547345013542683161477416855064032113",
              "4092547401589034517839581803135913704662038716011679653388144194916159194337"
             ],
             [
              "1",
              "0"
             ]
            ],
            "vk_gamma_2": [
             [
              "10857046999023057135944570762232829481370756359578518086990519993285655852781",
              "11559732032986387107991004021392285783925812861821192530917403151452391805634"
             ],
             [
              "8495653923123431417604973247489272438418190587263600148770280649306958101930",
              "4082367875863433681332203403145435568316851327593401208105741076214120093531"
             ],
             [
              "1",
              "0"
             ]
            ],
            "vk_delta_2": [
             [
              "8180975617555085204871380170175000102788026696454419980623914306436599128532",
              "3331351602225575281421494378134056754809940234852400414966398773366524857651"
             ],
             [
              "6618958641389095384073120287894321995303065876996255292488466535915374837928",
              "15994913618381028314207783518929321452652117210211011465746780807408599285748"
             ],
             [
              "1",
              "0"
             ]
            ],
            "vk_alphabeta_12": [
             [
              [
               "13925897310613440094806784950183916087490231756728293568879967017219591258265",
               "1068409956339393945899919029275985400811412945642571643626879607137142511765"
              ],
              [
               "21201703815532624101526062066461311644297843478684086565256139498673317456734",
               "5906077212303230519610593444593813776710650972494783038399013519138622830046"
              ],
              [
               "7606528894712726455250515735926872903578416945112066931488742795635517346383",
               "16861364081861477428029285837013243274187929565332804540580773022835737112994"
              ]
             ],
             [
              [
               "19429206652845099315545792148739899575942053876898352760809050688173131834146",
               "3047893487015852294640277270546765566101816812168661926296583122058742833836"
              ],
              [
               "9990318035187823499527076877139535164942469678523285598964303431352926949587",
               "498337238008796668905481771042554796740957624779710791356475247768939576082"
              ],
              [
               "7138509118339403845752672122412389474434921270918023730773158590367493296056",
               "15918629462784321119277979097192343871805004984723838910316967990022708168600"
              ]
             ]
            ],
            "IC": [
             [
              "2995383337499531323327725911773837629124627228848120457432312550688857178905",
              "21215991182081800694754080640319241769702201065024482750159044489357194795687",
              "1"
             ],
             [
              "5761179137850797061843544305795707280782387867962230142133021041966000269431",
              "21585470466311487968676403232824412651241430336544944589772100418897073181727",
              "1"
             ]
            ]
           }
        "#;
       let vkey =  electron_rs::verifier::near::parse_verification_key(vkey_str.to_string()).unwrap();
       let pvk = electron_rs::verifier::near::get_prepared_verifying_key(vkey);
       let result = electron_rs::verifier::near::verify_proof(pvk, proof_str.to_string(), pub_input_str.to_string()).unwrap();
       Ok(Response::new().add_attribute("result", result.to_string()))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetCount {} => to_binary(&query::count(deps)?),
    }
}

pub mod query {
    use super::*;

    pub fn count(deps: Deps) -> StdResult<GetCountResponse> {
        let state = STATE.load(deps.storage)?;
        Ok(GetCountResponse { count: state.count })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: GetCountResponse = from_binary(&res).unwrap();
        assert_eq!(17, value.count);
    }

    #[test]
    fn increment() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // beneficiary can release it
        let info = mock_info("anyone", &coins(2, "token"));
        let msg = ExecuteMsg::Increment {};
        let _res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // should increase counter by 1
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: GetCountResponse = from_binary(&res).unwrap();
        assert_eq!(18, value.count);
    }

    #[test]
    fn reset() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // beneficiary can release it
        let unauth_info = mock_info("anyone", &coins(2, "token"));
        let msg = ExecuteMsg::Reset { count: 5 };
        let res = execute(deps.as_mut(), mock_env(), unauth_info, msg);
        match res {
            Err(ContractError::Unauthorized {}) => {}
            _ => panic!("Must return unauthorized error"),
        }

        // only the original creator can reset the counter
        let auth_info = mock_info("creator", &coins(2, "token"));
        let msg = ExecuteMsg::Reset { count: 5 };
        let _res = execute(deps.as_mut(), mock_env(), auth_info, msg).unwrap();

        // should now be 5
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: GetCountResponse = from_binary(&res).unwrap();
        assert_eq!(5, value.count);
    }
}

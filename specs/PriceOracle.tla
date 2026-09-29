----------------------------- MODULE PriceOracle -----------------------------
EXTENDS Naturals, Integers, Sequences, FiniteSets

CONSTANTS Admins, Sources, Assets, NoAdmin, MaxHistoryLen, MaxPrice, MaxTime

\* Sentinel for "no price submitted yet".  It is a record with the same field
\* names as a real price entry so that TLC can compare it to a stored price
\* without a record/non-record equality error, but its values are outside the
\* ranges a real submission can produce (`price \in Nat`, `timestamp \in Nat`).
NoPrice == [source |-> "none", price |-> -1, timestamp |-> -1]

VARIABLES initialized, admin, authorizedSources, latestPrice, history, balances

vars == <<initialized, admin, authorizedSources, latestPrice, history, balances>>

Init ==
  /\ initialized = FALSE
  /\ admin = NoAdmin
  /\ authorizedSources = {}
  /\ latestPrice = [a \in Assets |-> NoPrice]
  /\ history = [a \in Assets |-> <<>>]
  /\ balances = [a \in Admins \cup Sources |-> 0]

Initialize(a) ==
  /\ initialized = FALSE
  /\ a \in Admins
  /\ initialized' = TRUE
  /\ admin' = a
  /\ UNCHANGED <<authorizedSources, latestPrice, history, balances>>

AddSource(caller, source) ==
  /\ initialized = TRUE
  /\ caller = admin
  /\ source \in Sources
  /\ authorizedSources' = authorizedSources \cup {source}
  /\ UNCHANGED <<initialized, admin, latestPrice, history, balances>>

SubmitPrice(source, asset, price, timestamp) ==
  /\ source \in authorizedSources
  /\ asset \in Assets
  /\ price \in Nat
  /\ latestPrice[asset] = NoPrice \/ timestamp >= latestPrice[asset].timestamp
  /\ latestPrice' = [latestPrice EXCEPT ![asset] = [source |-> source, price |-> price, timestamp |-> timestamp]]
  /\ history' = [history EXCEPT ![asset] =
        IF Len(@) < MaxHistoryLen
        THEN Append(@, latestPrice'[asset])
        ELSE Tail(Append(@, latestPrice'[asset]))]
  /\ UNCHANGED <<initialized, admin, authorizedSources, balances>>

NoOp ==
  UNCHANGED <<initialized, admin, authorizedSources, latestPrice, history, balances>>

\* SubmitPrice itself ranges over Nat; TLC cannot enumerate an infinite set, so
\* the model enumerates a bounded window and StateConstraint re-states the same
\* bound on every reachable state.  The checked bounds live in specs/PriceOracle.cfg.
Next ==
  \/ \E a \in Admins: Initialize(a)
  \/ \E c \in Admins, s \in Sources: AddSource(c, s)
  \/ \E s \in Sources, a \in Assets, p \in 0..MaxPrice, t \in 0..MaxTime: SubmitPrice(s, a, p, t)
  \/ NoOp

StateConstraint ==
  /\ \A a \in Assets:
       latestPrice[a] = NoPrice
       \/ /\ latestPrice[a].price <= MaxPrice
          /\ latestPrice[a].timestamp <= MaxTime
  /\ \A a \in Assets:
       \A i \in DOMAIN history[a]:
         /\ history[a][i].price <= MaxPrice
         /\ history[a][i].timestamp <= MaxTime

NoLossOfFunds == balances' = balances
PriceNonNegative == \A a \in Assets: latestPrice[a] = NoPrice \/ latestPrice[a].price >= 0
AccessControl == \A c \in Admins, s \in Sources: c # admin => ~AddSource(c, s)
WriteOnceInitialization == initialized => admin' = admin
PriceMonotonicity == \A a \in Assets:
  latestPrice[a] = NoPrice \/ latestPrice'[a] = NoPrice \/ latestPrice'[a].timestamp >= latestPrice[a].timestamp
BoundedStorage == \A a \in Assets: Len(history[a]) <= MaxHistoryLen

\* TLC only accepts state predicates under INVARIANT and temporal formulas under
\* PROPERTY, so the action-level properties above are wrapped as step properties
\* ([][A]_vars holds iff no step violates A; stuttering steps are allowed).
NoLossOfFundsStep == [][NoLossOfFunds]_vars
AccessControlStep == [][AccessControl]_vars
WriteOnceInitializationStep == [][WriteOnceInitialization]_vars
PriceMonotonicityStep == [][PriceMonotonicity]_vars

\* State-level restatements of the same guarantees, checked directly as invariants.
HistoryMonotonicTimestamps == \A a \in Assets:
  \A i \in 2..Len(history[a]): history[a][i].timestamp >= history[a][i - 1].timestamp

LatestMatchesHistory == \A a \in Assets:
  /\ (latestPrice[a] = NoPrice) = (Len(history[a]) = 0)
  /\ Len(history[a]) > 0 => history[a][Len(history[a])] = latestPrice[a]

InitializedHasAdmin == initialized => admin \in Admins

Spec == Init /\ [][Next]_vars

=============================================================================

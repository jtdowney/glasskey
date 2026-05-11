import glasslock
import qcheck

pub fn non_empty_list_from(
  element: qcheck.Generator(a),
) -> qcheck.Generator(List(a)) {
  qcheck.map2(element, qcheck.list_from(element), fn(x, xs) { [x, ..xs] })
}

pub fn user_verification_generator() -> qcheck.Generator(glasslock.Verification) {
  qcheck.from_generators(qcheck.return(glasslock.VerificationRequired), [
    qcheck.return(glasslock.VerificationPreferred),
    qcheck.return(glasslock.VerificationDiscouraged),
  ])
}

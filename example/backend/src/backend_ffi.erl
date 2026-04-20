-module(backend_ffi).
-export([term_encode/1, term_decode/1]).

term_encode(Term) ->
    erlang:term_to_binary(Term).

term_decode(Bin) ->
    try
        {ok, erlang:binary_to_term(Bin, [safe])}
    catch
        _:_ -> {error, nil}
    end.

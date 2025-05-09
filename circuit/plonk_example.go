package circuit

import "github.com/consensys/gnark/frontend"

type InnerCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`
}

// y == x**e
func (circuit *InnerCircuit) Define(api frontend.API) error {
	X := circuit.X
	Y := circuit.Y

	api.AssertIsEqual(X, Y)
	return nil
}
